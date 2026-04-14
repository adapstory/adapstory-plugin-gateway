package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
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
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Service encapsulating MCP proxy execution logic.
 *
 * <p>Extracted from {@code McpRouteController} (P3-21) to isolate proxy mechanics from HTTP routing
 * concerns, improving testability and adherence to SRP.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Resolve plugin backend URL from slug
 *   <li>Execute proxy request with header forwarding
 *   <li>Extract MCP JSON-RPC method for observability tagging
 * </ul>
 */
@Service
public class McpProxyService {

  private static final Logger log = LoggerFactory.getLogger(McpProxyService.class);

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
  private final MeterRegistry meterRegistry;

  /** Test-only URL overrides (slug -> base URL). */
  private final Map<String, String> urlOverrides = new ConcurrentHashMap<>();

  public McpProxyService(
      GatewayProperties properties,
      RestClient.Builder restClientBuilder,
      MeterRegistry meterRegistry) {
    this.properties = properties;
    this.restClient = restClientBuilder.build();
    this.meterRegistry = meterRegistry;
  }

  /**
   * Executes the MCP proxy: streams the request body to the plugin backend and copies the response
   * back.
   *
   * @param request incoming HTTP request
   * @param response outgoing HTTP response
   * @param targetUrl resolved plugin backend URL
   * @param slug plugin slug for observability
   * @param tenantId tenant identifier (may be null)
   * @throws IOException if an I/O error occurs during proxying
   */
  public void executeMcpProxy(
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

  /**
   * Copies safe request headers from the incoming servlet request to the outgoing {@link
   * HttpHeaders}, skipping hop-by-hop headers and Authorization.
   *
   * @param request incoming servlet request
   * @param headers outgoing REST client headers
   */
  public void copyRequestHeaders(HttpServletRequest request, HttpHeaders headers) {
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

  /**
   * Copies the response from the upstream client response to the servlet response, including status
   * code, headers (excluding hop-by-hop), and body.
   *
   * @param clientResponse upstream response
   * @param response downstream servlet response
   * @throws IOException if an I/O error occurs during body transfer
   */
  public void copyResponse(ClientHttpResponse clientResponse, HttpServletResponse response)
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
   * Resolves the plugin backend MCP URL for the given slug.
   *
   * @param slug plugin slug (e.g., "course-builder")
   * @return full URL like http://plugin-{slug}.plugins.svc.cluster.local:{port}/mcp
   */
  public String resolvePluginMcpUrl(String slug) {
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
   * Extracts the MCP JSON-RPC method name from a raw body string.
   *
   * <p>Uses regex for fast extraction without full JSON parsing.
   *
   * @param body JSON-RPC body string
   * @return method name (e.g., "tools/list", "tools/call") or "unknown"
   */
  public static String extractMcpMethod(String body) {
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
   * Sets an override URL for plugin backend (test-only).
   *
   * @param slug plugin slug
   * @param baseUrl base URL (without /mcp suffix)
   */
  public void overridePluginUrl(String slug, String baseUrl) {
    urlOverrides.put(slug, baseUrl);
  }
}
