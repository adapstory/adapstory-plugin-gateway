package com.adapstory.gateway.filter;

import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Service for computing permission intersection between JWT claims and plugin manifests.
 *
 * <p>Extracted from {@code PermissionEnforcementFilter} (P3-23) to isolate permission intersection
 * logic from HTTP filter mechanics, improving testability and SRP adherence.
 *
 * <p>Implements the intersection model (SEC-3.2): a permission is granted ONLY if it is present in
 * both JWT claims AND the current plugin manifest (from Redis/BC-02). Revoked permissions are
 * rejected immediately (ADAP-SEC-0010). When verification is impossible, fail-closed
 * (ADAP-SEC-0011).
 *
 * @see PermissionEnforcementFilter
 */
@Component
public class PermissionIntersectionService {
  private final GatewayPermissionRouteResolver routeResolver;
  private final PluginManifestPermissionResolver manifestPermissionResolver;
  private final PermissionIntersectionPolicy policy;

  public PermissionIntersectionService(
      GatewayPermissionRouteResolver routeResolver,
      PluginManifestPermissionResolver manifestPermissionResolver,
      PermissionIntersectionPolicy policy) {
    this.routeResolver = routeResolver;
    this.manifestPermissionResolver = manifestPermissionResolver;
    this.policy = policy;
  }

  /**
   * Resolves the required permission from the request path and HTTP method.
   *
   * <p>Extracts the route key from the gateway path format {@code
   * /api/bc-02/gateway/v1/api/{routeKey}/v1/...} and maps the HTTP method to the configured
   * permission string.
   *
   * @param path the request URI path
   * @param httpMethod the HTTP method (GET, POST, etc.)
   * @return the required permission string, or {@code null} if no mapping exists
   */
  public String resolveRequiredPermission(String path, String httpMethod) {
    return routeResolver.resolveRequiredPermission(path, httpMethod);
  }

  /**
   * Computes the full permission intersection result.
   *
   * <p>Performs the three-step intersection check:
   *
   * <ol>
   *   <li>Verify JWT contains the required permission
   *   <li>Fetch manifest permissions from cache or BC-02 REST
   *   <li>Verify manifest also contains the required permission
   * </ol>
   *
   * @param pluginId the plugin identifier for cache lookup
   * @param jwtPermissions permissions from JWT claims
   * @param requiredPermission the permission required for this route
   * @return the intersection result indicating grant, denial, or unavailability
   */
  public PermissionIntersectionResult computeIntersection(
      String pluginId, List<String> jwtPermissions, String requiredPermission) {
    PermissionIntersectionResult jwtResult =
        policy.evaluateJwtPermissions(jwtPermissions, requiredPermission);
    if (!jwtResult.isGranted()) {
      return jwtResult;
    }

    return manifestPermissionResolver
        .resolveManifestPermissions(pluginId)
        .map(
            manifestPermissions ->
                policy.evaluateManifestPermissions(
                    pluginId, requiredPermission, manifestPermissions))
        .orElseGet(() -> PermissionIntersectionResult.unavailable(pluginId));
  }
}
