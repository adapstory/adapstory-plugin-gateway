package com.adapstory.gateway.filter;

import com.adapstory.gateway.cache.PermissionCacheService;
import com.adapstory.gateway.config.GatewayProperties;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
public class PermissionIntersectionService {

  private static final String GATEWAY_PREFIX = "/api/bc-02/gateway/v1/api/";

  private final GatewayProperties properties;
  private final PermissionCacheService permissionCacheService;

  public PermissionIntersectionService(
      GatewayProperties properties, PermissionCacheService permissionCacheService) {
    this.properties = properties;
    this.permissionCacheService = permissionCacheService;
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
    if (!path.startsWith(GATEWAY_PREFIX)) {
      return null;
    }

    String afterPrefix = path.substring(GATEWAY_PREFIX.length());
    int slashIndex = afterPrefix.indexOf('/');
    String routeKey = slashIndex > 0 ? afterPrefix.substring(0, slashIndex) : afterPrefix;

    Map<String, Map<String, String>> routeMappings = properties.permissions().routeMappings();
    Map<String, String> methodMapping = routeMappings.get(routeKey);
    if (methodMapping == null) {
      return null;
    }

    return methodMapping.get(httpMethod.toUpperCase());
  }

  /**
   * Checks whether the required permission is present in the JWT claims.
   *
   * <p>Step 1 of the intersection model: if the JWT itself lacks the permission, reject immediately
   * without checking the manifest.
   *
   * @param jwtPermissions permissions extracted from the JWT
   * @param requiredPermission the permission required for this route
   * @return {@code true} if the JWT claims contain the required permission
   */
  public boolean hasJwtPermission(List<String> jwtPermissions, String requiredPermission) {
    return jwtPermissions.contains(requiredPermission);
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
  public IntersectionResult computeIntersection(
      String pluginId, List<String> jwtPermissions, String requiredPermission) {

    // Step 1: JWT check
    if (!hasJwtPermission(jwtPermissions, requiredPermission)) {
      return IntersectionResult.jwtMissing(requiredPermission);
    }

    // Step 2: Fetch manifest permissions from cache or BC-02
    Optional<List<String>> cached = permissionCacheService.getCachedPermissions(pluginId);

    List<String> manifestPermissions;
    if (cached.isPresent()) {
      manifestPermissions = cached.get();
    } else {
      Optional<List<String>> fetched = permissionCacheService.fetchAndCachePermissions(pluginId);
      if (fetched.isEmpty()) {
        return IntersectionResult.unavailable(pluginId);
      }
      manifestPermissions = fetched.get();
    }

    // Step 3: Intersection check — must be in BOTH JWT AND manifest
    if (!manifestPermissions.contains(requiredPermission)) {
      return IntersectionResult.revoked(pluginId, requiredPermission);
    }

    return IntersectionResult.granted();
  }

  /**
   * Result of a permission intersection computation.
   *
   * <p>Encapsulates the three possible outcomes:
   *
   * <ul>
   *   <li>{@link #granted()} — permission present in both JWT and manifest
   *   <li>{@link #jwtMissing(String)} — permission absent from JWT claims
   *   <li>{@link #revoked(String, String)} — permission in JWT but revoked in manifest
   *       (ADAP-SEC-0010)
   *   <li>{@link #unavailable(String)} — unable to verify (fail-closed, ADAP-SEC-0011)
   * </ul>
   */
  public static final class IntersectionResult {

    private final boolean granted;
    private final boolean unavailable;
    private final String errorCode;
    private final String requiredPermission;
    private final String pluginId;

    private IntersectionResult(
        boolean granted,
        boolean unavailable,
        String errorCode,
        String requiredPermission,
        String pluginId) {
      this.granted = granted;
      this.unavailable = unavailable;
      this.errorCode = errorCode;
      this.requiredPermission = requiredPermission;
      this.pluginId = pluginId;
    }

    /** Permission granted — present in both JWT and manifest. */
    public static IntersectionResult granted() {
      return new IntersectionResult(true, false, null, null, null);
    }

    /** Permission missing from JWT claims — reject without manifest check. */
    public static IntersectionResult jwtMissing(String requiredPermission) {
      return new IntersectionResult(false, false, "JWT_MISSING", requiredPermission, null);
    }

    /** Permission in JWT but revoked in manifest (ADAP-SEC-0010). */
    public static IntersectionResult revoked(String pluginId, String requiredPermission) {
      return new IntersectionResult(false, false, "ADAP-SEC-0010", requiredPermission, pluginId);
    }

    /** Unable to verify permissions — fail-closed (ADAP-SEC-0011). */
    public static IntersectionResult unavailable(String pluginId) {
      return new IntersectionResult(false, true, "ADAP-SEC-0011", null, pluginId);
    }

    public boolean isGranted() {
      return granted;
    }

    public boolean isUnavailable() {
      return unavailable;
    }

    public String getErrorCode() {
      return errorCode;
    }

    public String getRequiredPermission() {
      return requiredPermission;
    }

    public String getPluginId() {
      return pluginId;
    }
  }
}
