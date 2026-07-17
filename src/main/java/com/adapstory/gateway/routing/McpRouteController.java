package com.adapstory.gateway.routing;

import com.adapstory.gateway.filter.PluginMcpJwtClaimFilter;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.adapstory.gateway.util.PluginSlugValidator;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.trace.Span;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

/**
 * MCP маршрутизатор: проксирует JSON-RPC MCP вызовы к plugin backend.
 *
 * <p>Принимает POST {@code /internal/plugins/v1/{slug}/mcp}, валидирует slug, разрешает endpoint
 * plugin pod и делегирует проксирование в {@link McpProxyService}. Инжектирует обязательные
 * заголовки (INT-02): X-Tenant-Id, X-Request-Id, X-Correlation-Id. Тегирует mcp_method (tools/list
 * | tools/call) для observability.
 */
@RestController
@PermitAll
public class McpRouteController {

  private static final Logger log = LoggerFactory.getLogger(McpRouteController.class);

  private final McpProxyService mcpProxyService;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;
  private final AtomicInteger activeStreams = new AtomicInteger();

  public McpRouteController(
      McpProxyService mcpProxyService, ObjectMapper objectMapper, MeterRegistry meterRegistry) {
    this.mcpProxyService = mcpProxyService;
    this.objectMapper = objectMapper;
    this.meterRegistry = meterRegistry;
    meterRegistry.gauge("plugin_gateway_mcp_streams_active", activeStreams);
  }

  /**
   * Проксирует MCP JSON-RPC запрос к plugin backend.
   *
   * @param slug идентификатор плагина (e.g., "course-builder")
   * @param request входящий HTTP запрос
   * @param response исходящий HTTP ответ
   */
  @Operation(
      summary = "Proxy MCP JSON-RPC call to plugin backend",
      description =
          "Routes a JSON-RPC 2.0 MCP request to the plugin pod identified by slug. "
              + "Injects X-Tenant-Id, X-Request-Id, X-Correlation-Id headers.")
  @ApiResponse(responseCode = "200", description = "MCP response proxied from plugin backend")
  @ApiResponse(responseCode = "400", description = "Invalid plugin slug format")
  @ApiResponse(responseCode = "502", description = "Plugin pod unreachable or returned error")
  @PostMapping("/internal/plugins/v1/{slug}/mcp")
  public void proxyMcp(
      @Parameter(description = "Plugin slug identifier (e.g. 'course-builder')") @PathVariable
          String slug,
      HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    proxyMcpInternal(slug, request, response);
  }

  /** Opens or resumes the stateful MCP server-to-client SSE stream. */
  @GetMapping(
      path = "/internal/plugins/v1/{slug}/mcp",
      produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  public StreamingResponseBody proxyMcpStream(
      @PathVariable String slug, HttpServletRequest request, HttpServletResponse response) {
    return downstreamBody -> {
      activeStreams.incrementAndGet();
      try {
        proxyMcpInternal(slug, request, response);
      } finally {
        activeStreams.decrementAndGet();
      }
    };
  }

  /** Terminates one stateful MCP session on its bound provider pod. */
  @DeleteMapping("/internal/plugins/v1/{slug}/mcp")
  public void terminateMcpSession(
      @PathVariable String slug, HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    proxyMcpInternal(slug, request, response);
  }

  private void proxyMcpInternal(
      String slug, HttpServletRequest request, HttpServletResponse response) throws IOException {
    if (!PluginSlugValidator.isValidSlug(slug)) {
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

    String targetUrl = mcpProxyService.resolvePluginMcpUrl(slug);
    String tenantId = (String) request.getAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR);

    // Tag OTEL span
    Span currentSpan = Span.current();
    currentSpan.setAttribute("mcp.plugin_slug", slug);
    if (tenantId != null) {
      currentSpan.setAttribute("tenant.id", tenantId);
    }

    log.info("Proxying MCP request to plugin '{}' at {}", slug, targetUrl);

    try {
      mcpProxyService.executeMcpProxy(request, response, targetUrl, tenantId, slug);

      meterRegistry.counter("plugin_gateway_mcp_proxy_total", "status", "success").increment();
    } catch (McpSessionRoutingException ex) {
      if (response.isCommitted()) {
        log.error("MCP session routing failed after response commit for slug '{}'", slug);
        return;
      }
      meterRegistry.counter("plugin_gateway_mcp_proxy_total", "status", "error").increment();
      String reason = ex.reason().name().toLowerCase(java.util.Locale.ROOT);
      meterRegistry
          .counter(
              "plugin_gateway_mcp_session_routing_total", "outcome", "denied", "reason", reason)
          .increment();
      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          ex.httpStatus(),
          sessionRoutingErrorTitle(ex.httpStatus()),
          "MCP session routing is unavailable",
          Map.of("reason", reason));
    } catch (Exception ex) {
      if (response.isCommitted()) {
        log.error(
            "MCP proxy error after response committed for slug '{}': {}", slug, ex.getMessage());
        return;
      }

      log.error("MCP proxy error for slug '{}': {}", slug, ex.getMessage());
      meterRegistry.counter("plugin_gateway_mcp_proxy_total", "status", "error").increment();

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

  private static String sessionRoutingErrorTitle(int status) {
    HttpStatus resolved = HttpStatus.resolve(status);
    return resolved == null
        ? HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase()
        : resolved.getReasonPhrase();
  }

  /**
   * Delegates URL resolution to {@link McpProxyService}.
   *
   * @param slug plugin slug
   * @return resolved plugin MCP URL
   */
  String resolvePluginMcpUrl(String slug) {
    return mcpProxyService.resolvePluginMcpUrl(slug);
  }

  /**
   * Delegates MCP method extraction to {@link McpProxyService#extractMcpMethod(String)}.
   *
   * @param body JSON-RPC body
   * @return method name or "unknown"
   */
  static String extractMcpMethod(String body) {
    return McpProxyService.extractMcpMethod(body);
  }

  /**
   * Delegates URL override to {@link McpProxyService} (test-only).
   *
   * @param slug plugin slug
   * @param baseUrl base URL (without /mcp suffix)
   */
  void overridePluginUrl(String slug, String baseUrl) {
    mcpProxyService.overridePluginUrl(slug, baseUrl);
  }
}
