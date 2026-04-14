package com.adapstory.gateway.routing;

import com.adapstory.gateway.config.GatewayProperties;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Service for resolving gateway route keys from incoming request paths.
 *
 * <p>Extracted from {@code PluginRouteResolver} (P3-22) to isolate route resolution logic from
 * proxy execution, improving testability and SRP adherence.
 *
 * <p>Extracts the route key from paths matching the pattern {@code
 * /api/bc-02/gateway/v1/api/{routeKey}/...} and resolves the target backend URL from the configured
 * route mappings.
 */
@Service
public class RouteResolutionService {

  private static final String GATEWAY_API_PREFIX = "/api/bc-02/gateway/v1/api/";

  private final GatewayProperties properties;

  public RouteResolutionService(GatewayProperties properties) {
    this.properties = properties;
  }

  /**
   * Extracts the route key from a gateway request path.
   *
   * <p>Path format: {@code /api/bc-02/gateway/v1/api/{routeKey}/...}
   *
   * @param path the full request URI path
   * @return the extracted route key, or {@code null} if the path doesn't match the gateway prefix
   */
  public String extractRouteKey(String path) {
    if (!path.startsWith(GATEWAY_API_PREFIX)) {
      return null;
    }
    String afterPrefix = path.substring(GATEWAY_API_PREFIX.length());
    int slashIndex = afterPrefix.indexOf('/');
    return slashIndex > 0 ? afterPrefix.substring(0, slashIndex) : afterPrefix;
  }

  /**
   * Resolves the target backend base URL for a given route key.
   *
   * @param routeKey the route key extracted from the request path
   * @return the configured target base URL, or {@code null} if no route is configured
   */
  public String resolveTargetBaseUrl(String routeKey) {
    if (routeKey == null) {
      return null;
    }
    Map<String, String> routes = properties.routes();
    return routes.get(routeKey);
  }

  /**
   * Strips the gateway prefix from the request path, leaving the target BC path.
   *
   * <p>Pattern 4: strip {@code /api/bc-02/gateway/v1} prefix, forward exact remaining path.
   *
   * @param originalPath the full request URI path
   * @return the path with the gateway prefix removed
   */
  public String stripGatewayPrefix(String originalPath) {
    return originalPath.substring("/api/bc-02/gateway/v1".length());
  }

  /**
   * Builds the full target URI by combining the base URL, stripped path, and query string.
   *
   * @param targetBaseUrl the resolved backend base URL
   * @param originalPath the original request URI path
   * @param queryString the query string (may be null)
   * @return the complete target URI string
   */
  public String buildTargetUri(String targetBaseUrl, String originalPath, String queryString) {
    String targetPath = stripGatewayPrefix(originalPath);
    return targetBaseUrl + targetPath + (queryString != null ? "?" + queryString : "");
  }
}
