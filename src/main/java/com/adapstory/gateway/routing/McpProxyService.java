package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.filter.PluginMcpJwtClaimFilter;
import com.adapstory.gateway.util.McpHttpHeaders;
import io.micrometer.core.instrument.MeterRegistry;
import io.opentelemetry.api.trace.Span;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

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

  private static final Pattern MCP_METHOD_PATTERN =
      Pattern.compile("\"method\"\\s*:\\s*\"([^\"]+)\"");
  private static final String UNKNOWN_METHOD = "unknown";

  private final GatewayProperties properties;
  private final McpProxyTransportPort proxyTransport;
  private final McpSessionAffinityRouter sessionAffinityRouter;
  private final MeterRegistry meterRegistry;

  /** Test-only URL overrides (slug -> base URL). */
  private final Map<String, String> urlOverrides = new ConcurrentHashMap<>();

  public McpProxyService(
      GatewayProperties properties,
      McpProxyTransportPort proxyTransport,
      McpSessionAffinityRouter sessionAffinityRouter,
      MeterRegistry meterRegistry) {
    this.properties = properties;
    this.proxyTransport = proxyTransport;
    this.sessionAffinityRouter = sessionAffinityRouter;
    this.meterRegistry = meterRegistry;
  }

  /**
   * Executes the MCP proxy: streams the request body to the plugin backend and copies the response
   * back.
   *
   * @param request incoming HTTP request
   * @param response outgoing HTTP response
   * @param targetUrl resolved plugin backend URL
   * @param tenantId tenant identifier (may be null)
   * @throws IOException if an I/O error occurs during proxying
   */
  public void executeMcpProxy(
      HttpServletRequest request,
      HttpServletResponse response,
      String targetUrl,
      String tenantId,
      String routeSlug)
      throws IOException {
    String sessionId = request.getHeader(McpHttpHeaders.SESSION_ID);
    McpSessionRoute sessionRoute =
        sessionAffinityRouter.resolve(
            URI.create(targetUrl),
            tenantId,
            routeSlug,
            sessionId,
            request.getHeader(IntegrationHeaders.HEADER_REQUEST_ID));
    var sessionContext =
        new ProxySessionContext(request, sessionRoute, tenantId, routeSlug, sessionId);
    proxyTransport.proxy(
        request,
        response,
        sessionRoute.backendEndpoint(),
        tenantId,
        (status, headers, backendEndpoint) ->
            beforeCommit(sessionContext, status, headers, backendEndpoint));
    String mcpMethod = extractMcpMethodFromRequest(request);
    Span.current().setAttribute("mcp.method", mcpMethod);
    String metricMethod =
        switch (mcpMethod) {
          case "tools/list", "tools/call" -> mcpMethod;
          default -> "other";
        };
    meterRegistry
        .counter("plugin_gateway_mcp_method_total", "mcp_method", metricMethod)
        .increment();
  }

  /**
   * Resolves the plugin backend MCP URL for the given slug.
   *
   * @param slug plugin slug (e.g., "course-builder")
   * @return full URL like http://plugin-{slug}.plugins.svc.cluster.local:{port}/mcp
   */
  public String resolvePluginMcpUrl(String slug) {
    String override = urlOverrides.get(slug);
    if (override != null) {
      return withoutTrailingSlash(override) + "/mcp";
    }
    GatewayProperties.McpConfig cfg = properties.mcp();
    for (GatewayProperties.PluginRoute route : cfg.pluginRoutes()) {
      if (route.slug().equals(slug)) {
        return withoutTrailingSlash(route.sessionAffinityBaseUrl()) + "/mcp";
      }
    }
    String host = String.format(cfg.sessionAffinityHostTemplate(), slug);
    return String.format("http://%s:%d/mcp", host, cfg.pluginPodPort());
  }

  /**
   * Resolves the plugin backend base URL for REST and MCP traffic.
   *
   * @param slug plugin slug (e.g., "course-builder")
   * @return base URL like http://plugin-{slug}.plugins.svc.cluster.local:{port}
   */
  public String resolvePluginBaseUrl(String slug) {
    // Check test overrides first
    String override = urlOverrides.get(slug);
    if (override != null) {
      return withoutTrailingSlash(override);
    }

    GatewayProperties.McpConfig cfg = properties.mcp();
    for (GatewayProperties.PluginRoute route : cfg.pluginRoutes()) {
      if (route.slug().equals(slug)) {
        return withoutTrailingSlash(route.baseUrl());
      }
    }
    String host = String.format(cfg.pluginHostTemplate(), slug);
    return String.format("http://%s:%d", host, cfg.pluginPodPort());
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
      return UNKNOWN_METHOD;
    }
    Matcher matcher = MCP_METHOD_PATTERN.matcher(body);
    if (matcher.find()) {
      return matcher.group(1);
    }
    return UNKNOWN_METHOD;
  }

  private String extractMcpMethodFromRequest(HttpServletRequest request) {
    // Try to read from cached body if available, otherwise return unknown
    // The body has already been consumed by the proxy, so we rely on content-type check
    if (request.getContentType() != null
        && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE)) {
      String cachedMethod = (String) request.getAttribute(PluginMcpJwtClaimFilter.MCP_METHOD_ATTR);
      if (cachedMethod != null) {
        return cachedMethod;
      }
    }
    return UNKNOWN_METHOD;
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

  private static String withoutTrailingSlash(String value) {
    if (value.endsWith("/")) {
      return value.substring(0, value.length() - 1);
    }
    return value;
  }

  private void beforeCommit(
      ProxySessionContext context,
      HttpStatusCode status,
      HttpHeaders headers,
      URI backendEndpoint) {
    String responseSessionId = headers.getFirst(McpHttpHeaders.SESSION_ID);
    if (context.sessionRoute().newSession() && status.is2xxSuccessful()) {
      if (!McpHttpHeaders.isCanonicalSessionId(responseSessionId)) {
        throw new McpSessionRoutingException(McpSessionRoutingException.Reason.INVALID_SESSION);
      }
      sessionAffinityRouter.bind(
          context.tenantId(), context.routeSlug(), responseSessionId, backendEndpoint);
      return;
    }
    if (!context.sessionRoute().newSession()
        && responseSessionId != null
        && !responseSessionId.equals(context.requestSessionId())) {
      throw new McpSessionRoutingException(McpSessionRoutingException.Reason.INVALID_SESSION);
    }
    if ("DELETE".equals(context.request().getMethod())
        && (status.is2xxSuccessful() || status.value() == 404)) {
      sessionAffinityRouter.terminate(
          context.tenantId(), context.routeSlug(), context.requestSessionId());
    }
  }

  private record ProxySessionContext(
      HttpServletRequest request,
      McpSessionRoute sessionRoute,
      String tenantId,
      String routeSlug,
      String requestSessionId) {}
}
