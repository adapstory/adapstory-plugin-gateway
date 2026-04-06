package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.filter.PluginMcpJwtClaimFilter;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.trace.Span;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * MCP маршрутизатор: проксирует JSON-RPC MCP вызовы к plugin backend.
 *
 * <p>Принимает POST /internal/plugins/{slug}/mcp, разрешает endpoint plugin pod из конфигурации и
 * проксирует запрос на /mcp backend. Инжектирует обязательные заголовки (INT-02): X-Tenant-Id,
 * X-Request-Id, X-Correlation-Id. Тегирует mcp_method (tools/list | tools/call) для observability.
 */
@RestController
@RequestMapping("/internal/plugins")
public class McpRouteController {

  private static final Logger log = LoggerFactory.getLogger(McpRouteController.class);

  private static final Pattern SLUG_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]*$");
  private static final Pattern MCP_METHOD_PATTERN =
      Pattern.compile("\"method\"\\s*:\\s*\"([^\"]+)\"");

  private static final Set<String> HOP_BY_HOP_HEADERS =
      Set.of(
          "connection",
          "content-length",
          "keep-alive",
          "proxy-authenticate",
          "proxy-authorization",
          "te",
          "trailers",
          "transfer-encoding",
          "upgrade",
          "host");

  private final GatewayProperties properties;
  private final RestClient restClient;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;

  /** Test-only URL overrides (slug -> base URL). */
  private final Map<String, String> urlOverrides = new ConcurrentHashMap<>();

  public McpRouteController(
      GatewayProperties properties,
      RestClient.Builder restClientBuilder,
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry) {
    this.properties = properties;
    this.restClient = restClientBuilder.build();
    this.objectMapper = objectMapper;
    this.meterRegistry = meterRegistry;
  }

  /**
   * Проксирует MCP JSON-RPC запрос к plugin backend.
   *
   * @param slug идентификатор плагина (e.g., "course-builder")
   * @param request входящий HTTP запрос
   * @param response исходящий HTTP ответ
   */
  @PostMapping("/{slug}/mcp")
  public void proxyMcp(
      @PathVariable String slug, HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    if (!SLUG_PATTERN.matcher(slug).matches()) {
      log.warn("MCP proxy rejected: invalid slug '{}'", slug);
      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          400,
          "Bad Request",
          "Invalid plugin slug format",
          Map.of("slug", slug));
      return;
    }

    String targetUrl = resolvePluginMcpUrl(slug);
    String tenantId = (String) request.getAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR);

    // Tag OTEL span
    Span currentSpan = Span.current();
    currentSpan.setAttribute("mcp.plugin_slug", slug);
    if (tenantId != null) {
      currentSpan.setAttribute("tenant.id", tenantId);
    }

    log.info("Proxying MCP request to plugin '{}' at {}", slug, targetUrl);

    try {
      executeMcpProxy(request, response, targetUrl, slug, tenantId);

      meterRegistry
          .counter("plugin_gateway_mcp_proxy_total", "slug", slug, "status", "success")
          .increment();
    } catch (Exception ex) {
      if (response.isCommitted()) {
        log.error(
            "MCP proxy error after response committed for slug '{}': {}", slug, ex.getMessage());
        return;
      }

      log.error("MCP proxy error for slug '{}': {}", slug, ex.getMessage());
      meterRegistry
          .counter("plugin_gateway_mcp_proxy_total", "slug", slug, "status", "error")
          .increment();

      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          502,
          "Bad Gateway",
          "Error proxying MCP request to plugin backend",
          Map.of("slug", slug));
    }
  }

  private void executeMcpProxy(
      HttpServletRequest request,
      HttpServletResponse response,
      String targetUrl,
      String slug,
      String tenantId)
      throws IOException {
    restClient
        .post()
        .uri(URI.create(targetUrl))
        .headers(
            headers -> {
              copyRequestHeaders(request, headers);
              // Inject mandatory INT-02 headers
              if (tenantId != null) {
                headers.set(IntegrationHeaders.HEADER_TENANT_ID, tenantId);
              }
              String requestId = request.getHeader(IntegrationHeaders.HEADER_REQUEST_ID);
              if (requestId != null) {
                headers.set(IntegrationHeaders.HEADER_REQUEST_ID, requestId);
              }
              String correlationId = request.getHeader(IntegrationHeaders.HEADER_CORRELATION_ID);
              if (correlationId != null) {
                headers.set(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);
              }
              headers.set(IntegrationHeaders.HEADER_SOURCE_SERVICE, "plugin-gateway");
            })
        .body(
            (StreamingHttpOutputMessage.Body)
                outputStream -> {
                  try (InputStream is = request.getInputStream()) {
                    is.transferTo(outputStream);
                  }
                })
        .exchange(
            (req, clientResponse) -> {
              copyResponse(clientResponse, response);

              // Try to extract mcp_method for observability
              String mcpMethod = extractMcpMethodFromRequest(request);
              Span.current().setAttribute("mcp.method", mcpMethod);
              meterRegistry
                  .counter("plugin_gateway_mcp_method_total", "slug", slug, "mcp_method", mcpMethod)
                  .increment();

              return null;
            });
  }

  private void copyRequestHeaders(HttpServletRequest request, HttpHeaders headers) {
    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      if (HOP_BY_HOP_HEADERS.contains(headerName.toLowerCase())) {
        continue;
      }
      if (headerName.equalsIgnoreCase(HttpHeaders.AUTHORIZATION)) {
        continue; // Don't forward plugin JWT to target backend
      }
      Enumeration<String> values = request.getHeaders(headerName);
      while (values.hasMoreElements()) {
        headers.add(headerName, values.nextElement());
      }
    }
  }

  private void copyResponse(ClientHttpResponse clientResponse, HttpServletResponse response)
      throws IOException {
    response.setStatus(clientResponse.getStatusCode().value());

    clientResponse
        .getHeaders()
        .forEach(
            (name, values) -> {
              if (!HOP_BY_HOP_HEADERS.contains(name.toLowerCase())) {
                for (String value : values) {
                  response.addHeader(name, value);
                }
              }
            });

    try (InputStream body = clientResponse.getBody()) {
      body.transferTo(response.getOutputStream());
    }
  }

  /**
   * Разрешает URL plugin backend для MCP endpoint.
   *
   * @param slug plugin slug (e.g., "course-builder")
   * @return полный URL вида http://plugin-{slug}.plugins.svc.cluster.local:{port}/mcp
   */
  String resolvePluginMcpUrl(String slug) {
    // Check test overrides first
    String override = urlOverrides.get(slug);
    if (override != null) {
      return override + "/mcp";
    }

    GatewayProperties.McpConfig cfg = properties.mcp();
    String host = String.format(cfg.pluginHostTemplate(), slug);
    return String.format("http://%s:%d/mcp", host, cfg.pluginPodPort());
  }

  /**
   * Извлекает MCP method из JSON-RPC body запроса.
   *
   * <p>Использует regex для быстрого извлечения без полного парсинга JSON.
   *
   * @param body JSON-RPC body
   * @return method (e.g., "tools/list", "tools/call") или "unknown"
   */
  static String extractMcpMethod(String body) {
    if (body == null || body.isBlank()) {
      return "unknown";
    }
    Matcher matcher = MCP_METHOD_PATTERN.matcher(body);
    if (matcher.find()) {
      return matcher.group(1);
    }
    return "unknown";
  }

  private String extractMcpMethodFromRequest(HttpServletRequest request) {
    // Try to read from cached body if available, otherwise return unknown
    // The body has already been consumed by the proxy, so we rely on content-type check
    try {
      if (request.getContentType() != null
          && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)) {
        // Body was already forwarded; try to get from request attribute if set
        String cachedMethod = (String) request.getAttribute("mcp.method");
        if (cachedMethod != null) {
          return cachedMethod;
        }
      }
    } catch (Exception ignored) {
      // Fallback to unknown
    }
    return "unknown";
  }

  /**
   * Устанавливает override URL для plugin backend (только для тестов).
   *
   * @param slug plugin slug
   * @param baseUrl base URL (без /mcp suffix)
   */
  void overridePluginUrl(String slug, String baseUrl) {
    urlOverrides.put(slug, baseUrl);
  }
}
