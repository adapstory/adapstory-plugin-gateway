package com.adapstory.gateway.routing;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * REST прокси-контроллер Plugin Gateway.
 *
 * <p>Разрешает /api/bc-02/gateway/v1/api/{bc}/... в целевой BC URL, стрипит /api/bc-02/gateway/v1
 * prefix и проксирует запрос с circuit breaker защитой. Pattern 4: Gateway path =
 * /api/bc-02/gateway/v1/ prefix + exact core BC path.
 */
@RestController
@RequestMapping("/api/bc-02/gateway/v1")
public class PluginRouteResolver {

  private static final Logger log = LoggerFactory.getLogger(PluginRouteResolver.class);
  private static final String GATEWAY_API_PREFIX = "/api/bc-02/gateway/v1/api/";
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
  private final CircuitBreakerRegistry circuitBreakerRegistry;
  private final ObjectMapper objectMapper;

  public PluginRouteResolver(
      GatewayProperties properties,
      RestClient.Builder restClientBuilder,
      CircuitBreakerRegistry circuitBreakerRegistry,
      ObjectMapper objectMapper) {
    this.properties = properties;
    this.restClient = restClientBuilder.build();
    this.circuitBreakerRegistry = circuitBreakerRegistry;
    this.objectMapper = objectMapper;
  }

  @RequestMapping("/api/**")
  public void proxy(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String originalPath = request.getRequestURI();
    String routeKey = extractRouteKey(originalPath);

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

    String targetBaseUrl = properties.routes().get(routeKey);
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

    // Pattern 4: strip /api/bc-02/gateway/v1 prefix, forward exact remaining path
    String targetPath = originalPath.substring("/api/bc-02/gateway/v1".length());
    String queryString = request.getQueryString();
    String targetUri = targetBaseUrl + targetPath + (queryString != null ? "?" + queryString : "");

    CircuitBreaker circuitBreaker = circuitBreakerRegistry.circuitBreaker(routeKey);

    try {
      circuitBreaker.executeRunnable(
          () -> {
            try {
              executeProxy(request, response, targetUri);
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

  private void executeProxy(
      HttpServletRequest request, HttpServletResponse response, String targetUri)
      throws IOException {
    HttpMethod method = HttpMethod.valueOf(request.getMethod());
    boolean hasBody =
        method == HttpMethod.POST || method == HttpMethod.PUT || method == HttpMethod.PATCH;

    if (hasBody) {
      restClient
          .method(method)
          .uri(URI.create(targetUri))
          .headers(headers -> copyRequestHeaders(request, headers))
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
                return null;
              });
    } else {
      restClient
          .method(method)
          .uri(URI.create(targetUri))
          .headers(headers -> copyRequestHeaders(request, headers))
          .exchange(
              (req, clientResponse) -> {
                copyResponse(clientResponse, response);
                return null;
              });
    }
  }

  private void copyRequestHeaders(HttpServletRequest request, HttpHeaders headers) {
    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      if (HOP_BY_HOP_HEADERS.contains(headerName.toLowerCase())) {
        continue;
      }
      if (headerName.equalsIgnoreCase(HttpHeaders.AUTHORIZATION)) {
        continue; // Don't forward plugin JWT to target BC
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

  /** Extract route key from path. Path format: /api/bc-02/gateway/v1/api/{routeKey}/... */
  String extractRouteKey(String path) {
    if (!path.startsWith(GATEWAY_API_PREFIX)) {
      return null;
    }
    String afterPrefix = path.substring(GATEWAY_API_PREFIX.length());
    int slashIndex = afterPrefix.indexOf('/');
    return slashIndex > 0 ? afterPrefix.substring(0, slashIndex) : afterPrefix;
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
