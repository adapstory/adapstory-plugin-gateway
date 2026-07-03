package com.adapstory.gateway.routing;

import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Proxies browser-facing first-party plugin REST routes to installed plugin backends. */
@PermitAll
@RestController
public class FirstPartyPluginRestRouteController {

  private static final Logger log =
      LoggerFactory.getLogger(FirstPartyPluginRestRouteController.class);
  private static final Pattern PLUGIN_SLUG_PATTERN = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");
  private static final String DETAIL_PLUGIN_SLUG = "pluginSlug";

  private final McpProxyService mcpProxyService;
  private final ProxyExecutionService proxyExecutionService;
  private final CircuitBreakerRegistry circuitBreakerRegistry;
  private final ObjectMapper objectMapper;

  public FirstPartyPluginRestRouteController(
      McpProxyService mcpProxyService,
      ProxyExecutionService proxyExecutionService,
      CircuitBreakerRegistry circuitBreakerRegistry,
      ObjectMapper objectMapper) {
    this.mcpProxyService = mcpProxyService;
    this.proxyExecutionService = proxyExecutionService;
    this.circuitBreakerRegistry = circuitBreakerRegistry;
    this.objectMapper = objectMapper;
  }

  /**
   * Proxies a plugin REST request from the browser to the selected plugin backend.
   *
   * @param slug plugin slug from the request path
   * @param request servlet request
   * @param response servlet response
   * @throws IOException when target proxy call fails with checked IO errors
   */
  @RequestMapping("/api/plugins/{slug}/v1/**")
  public void proxy(
      @PathVariable String slug, HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (!PLUGIN_SLUG_PATTERN.matcher(slug).matches()) {
      writeError(
          response,
          request,
          400,
          "Bad Request",
          "Invalid plugin slug",
          Map.of(DETAIL_PLUGIN_SLUG, slug));
      return;
    }

    String targetUri = buildTargetUri(mcpProxyService.resolvePluginBaseUrl(slug), request);
    var circuitBreaker = circuitBreakerRegistry.circuitBreaker("plugin-rest:" + slug);

    try {
      circuitBreaker.executeRunnable(
          () -> {
            try {
              proxyExecutionService.executeProxy(request, response, targetUri);
            } catch (IOException ex) {
              throw new UncheckedIOException("Plugin REST proxy IO error", ex);
            }
          });
    } catch (io.github.resilience4j.circuitbreaker.CallNotPermittedException ex) {
      log.warn("Plugin REST circuit breaker open for slug '{}': {}", slug, ex.getMessage());
      writeError(
          response,
          request,
          503,
          "Service Unavailable",
          "Plugin backend is temporarily unavailable",
          Map.of(DETAIL_PLUGIN_SLUG, slug, "circuitBreakerState", "OPEN"));
    } catch (UncheckedIOException ex) {
      if (response.isCommitted()) {
        log.error("Plugin REST proxy error after response committed for slug '{}'", slug, ex);
        return;
      }
      log.error("Plugin REST proxy error for slug '{}'", slug, ex);
      writeError(
          response,
          request,
          502,
          "Bad Gateway",
          "Error proxying to plugin backend",
          Map.of(DETAIL_PLUGIN_SLUG, slug));
    }
  }

  private static String buildTargetUri(String targetBaseUrl, HttpServletRequest request) {
    String queryString = request.getQueryString();
    return targetBaseUrl + request.getRequestURI() + (queryString != null ? "?" + queryString : "");
  }

  private void writeError(
      HttpServletResponse response,
      HttpServletRequest request,
      int status,
      String error,
      String message,
      Map<String, Object> details)
      throws IOException {
    PluginSecurityContext pluginContext =
        (PluginSecurityContext) request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);
    Map<String, Object> enrichedDetails = new LinkedHashMap<>(details);
    if (pluginContext != null) {
      enrichedDetails.put("pluginId", pluginContext.pluginId());
    }
    GatewayErrorWriter.writeError(
        objectMapper, response, request, status, error, message, enrichedDetails);
  }
}
