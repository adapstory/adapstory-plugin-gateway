package com.adapstory.gateway.routing;

import com.adapstory.gateway.filter.PluginMcpJwtClaimFilter;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.trace.Span;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * MCP маршрутизатор: проксирует JSON-RPC MCP вызовы к plugin backend.
 *
 * <p>Принимает POST /internal/plugins/{slug}/mcp, валидирует slug, разрешает endpoint plugin pod и
 * делегирует проксирование в {@link McpProxyService}. Инжектирует обязательные заголовки (INT-02):
 * X-Tenant-Id, X-Request-Id, X-Correlation-Id. Тегирует mcp_method (tools/list | tools/call) для
 * observability.
 */
@RestController
@RequestMapping("/internal/plugins")
public class McpRouteController {

  private static final Logger log = LoggerFactory.getLogger(McpRouteController.class);

  private static final Pattern SLUG_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]*$");

  private final McpProxyService mcpProxyService;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;

  public McpRouteController(
      McpProxyService mcpProxyService, ObjectMapper objectMapper, MeterRegistry meterRegistry) {
    this.mcpProxyService = mcpProxyService;
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
  @Operation(
      summary = "Proxy MCP JSON-RPC call to plugin backend",
      description =
          "Routes a JSON-RPC 2.0 MCP request to the plugin pod identified by slug. "
              + "Injects X-Tenant-Id, X-Request-Id, X-Correlation-Id headers.")
  @ApiResponse(responseCode = "200", description = "MCP response proxied from plugin backend")
  @ApiResponse(responseCode = "400", description = "Invalid plugin slug format")
  @ApiResponse(responseCode = "502", description = "Plugin pod unreachable or returned error")
  @PostMapping("/{slug}/mcp")
  public void proxyMcp(
      @Parameter(description = "Plugin slug identifier (e.g. 'course-builder')") @PathVariable
          String slug,
      HttpServletRequest request,
      HttpServletResponse response)
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
      mcpProxyService.executeMcpProxy(request, response, targetUrl, slug, tenantId);

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
