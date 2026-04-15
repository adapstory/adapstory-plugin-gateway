package com.adapstory.gateway.routing;

import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST прокси-контроллер Plugin Gateway.
 *
 * <p>Разрешает /api/bc-02/gateway/v1/api/{bc}/... в целевой BC URL, стрипит /api/bc-02/gateway/v1
 * prefix и проксирует запрос с circuit breaker защитой. Pattern 4: Gateway path =
 * /api/bc-02/gateway/v1/ prefix + exact core BC path.
 *
 * <p>Delegates route resolution to {@link RouteResolutionService} and proxy execution to {@link
 * ProxyExecutionService} (P3-22 SOLID refactoring).
 */
@PermitAll
@RestController
@RequestMapping("/api/bc-02/gateway/v1")
public class PluginRouteResolver {

  private static final Logger log = LoggerFactory.getLogger(PluginRouteResolver.class);

  private final RouteResolutionService routeResolutionService;
  private final ProxyExecutionService proxyExecutionService;
  private final CircuitBreakerRegistry circuitBreakerRegistry;
  private final ObjectMapper objectMapper;

  public PluginRouteResolver(
      RouteResolutionService routeResolutionService,
      ProxyExecutionService proxyExecutionService,
      CircuitBreakerRegistry circuitBreakerRegistry,
      ObjectMapper objectMapper) {
    this.routeResolutionService = routeResolutionService;
    this.proxyExecutionService = proxyExecutionService;
    this.circuitBreakerRegistry = circuitBreakerRegistry;
    this.objectMapper = objectMapper;
  }

  @Operation(
      summary = "Proxy REST request to target BC service",
      description =
          "Resolves the target BC from the URL path and proxies the request with "
              + "circuit breaker protection. Strips /api/bc-02/gateway/v1 prefix.")
  @ApiResponse(responseCode = "200", description = "Response proxied from target BC")
  @ApiResponse(responseCode = "404", description = "Route not configured for the target BC")
  @ApiResponse(responseCode = "502", description = "Target BC returned an error")
  @ApiResponse(responseCode = "503", description = "Circuit breaker open — target BC unavailable")
  @RequestMapping("/api/**")
  public void proxy(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String originalPath = request.getRequestURI();
    String routeKey = routeResolutionService.extractRouteKey(originalPath);

    if (routeKey == null) {
      writeError(
          response,
          request,
          404,
          "Not Found",
          "Cannot resolve route from path: " + originalPath,
          Map.of());
      return;
    }

    String targetBaseUrl = routeResolutionService.resolveTargetBaseUrl(routeKey);
    if (targetBaseUrl == null) {
      writeError(
          response,
          request,
          404,
          "Not Found",
          "No target BC configured for route: " + routeKey,
          Map.of());
      return;
    }

    String targetUri =
        routeResolutionService.buildTargetUri(
            targetBaseUrl, originalPath, request.getQueryString());

    CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(routeKey);

    try {
      circuitBreaker.executeRunnable(
          () -> {
            try {
              proxyExecutionService.executeProxy(request, response, targetUri);
            } catch (IOException ex) {
              throw new RuntimeException("Proxy IO error", ex);
            }
          });
    } catch (io.github.resilience4j.circuitbreaker.CallNotPermittedException ex) {
      log.warn("Circuit breaker open for route '{}': {}", routeKey, ex.getMessage());
      writeError(
          response,
          request,
          503,
          "Service Unavailable",
          "Target service '" + routeKey + "' is temporarily unavailable",
          Map.of("route", routeKey, "circuitBreakerState", "OPEN"));
    } catch (RuntimeException ex) {
      if (response.isCommitted()) {
        log.error(
            "Proxy error after response committed for route '{}': {}", routeKey, ex.getMessage());
        return;
      }
      log.error("Proxy error for route '{}': {}", routeKey, ex.getMessage());
      writeError(
          response,
          request,
          502,
          "Bad Gateway",
          "Error proxying to target service: " + routeKey,
          Map.of("route", routeKey));
    }
  }

  /** Extract route key from path — delegates to {@link RouteResolutionService}. */
  String extractRouteKey(String path) {
    return routeResolutionService.extractRouteKey(path);
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
    if (pluginContext != null) {
      details = new java.util.LinkedHashMap<>(details);
      details.put("pluginId", pluginContext.pluginId());
    }

    GatewayErrorWriter.writeError(objectMapper, response, request, status, error, message, details);
  }
}
