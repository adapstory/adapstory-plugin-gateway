package com.adapstory.gateway.filter;

import com.adapstory.gateway.cache.PermissionCacheService;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/**
 * Фильтр проверки разрешений плагина — intersection model (Story SEC-3.2).
 *
 * <p>Разрешение выдаётся ТОЛЬКО если требуемая permission присутствует в JWT claims И в текущем
 * манифесте плагина (из Redis/BC-02). Отозванная permission отклоняется немедленно (ADAP-SEC-0010),
 * без ожидания истечения JWT. При невозможности проверки — fail-closed (ADAP-SEC-0011).
 *
 * <p>Delegates permission intersection computation to {@link PermissionIntersectionService} (P3-23
 * SOLID refactoring).
 */
@Component
// M-7: Filter ordering is defined via SecurityConfig.addFilterAfter() chain, not @Order.
// Removed @Order(2) to be consistent with other filters in the chain.
public class PermissionEnforcementFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(PermissionEnforcementFilter.class);
  private static final String GATEWAY_PREFIX = "/api/bc-02/gateway/v1/api/";

  static final String ERROR_CODE_PERMISSION_REVOKED = "ADAP-SEC-0010";
  static final String ERROR_CODE_PERMISSION_UNAVAILABLE = "ADAP-SEC-0011";

  private static final String METRIC_CACHE_HIT = "plugin_gateway_permission_cache_hit_total";
  private static final String METRIC_DENIED = "plugin_gateway_permission_denied_total";
  private static final String METRIC_UNAVAILABLE = "plugin_gateway_permission_unavailable_total";

  private final PermissionIntersectionService intersectionService;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;

  public PermissionEnforcementFilter(
      GatewayProperties properties,
      ObjectMapper objectMapper,
      PermissionCacheService permissionCacheService,
      MeterRegistry meterRegistry) {
    this.intersectionService =
        new PermissionIntersectionService(properties, permissionCacheService);
    this.objectMapper = objectMapper;
    this.meterRegistry = meterRegistry;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    PluginSecurityContext pluginContext =
        (PluginSecurityContext) request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);

    if (pluginContext == null) {
      filterChain.doFilter(request, response);
      return;
    }

    String path = request.getRequestURI();
    String method = request.getMethod();
    String pluginId = pluginContext.pluginId();

    String requiredPermission = intersectionService.resolveRequiredPermission(path, method);
    if (requiredPermission == null) {
      log.warn("No permission mapping found for path={} method={}", path, method);
      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          403,
          "Forbidden",
          "No permission mapping configured for this route",
          buildDetails(pluginContext, null));
      return;
    }

    // Step 1: Check JWT claims first — if JWT itself lacks the permission, reject immediately
    List<String> jwtPermissions = pluginContext.permissions();
    if (!intersectionService.hasJwtPermission(jwtPermissions, requiredPermission)) {
      log.warn(
          "Permission denied for plugin {}: required={}, jwt={}",
          pluginId,
          requiredPermission,
          jwtPermissions);
      meterRegistry
          .counter(METRIC_DENIED, "pluginId", pluginId, "errorCode", "JWT_MISSING")
          .increment();

      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          403,
          "Forbidden",
          String.format(
              "Plugin '%s' does not have permission '%s'",
              extractShortPluginId(pluginId), requiredPermission),
          buildDetails(pluginContext, requiredPermission));
      return;
    }

    // Step 2 & 3: Compute full intersection (manifest fetch + intersection check)
    PermissionIntersectionService.IntersectionResult result =
        intersectionService.computeIntersection(pluginId, jwtPermissions, requiredPermission);

    if (result.isUnavailable()) {
      // Fail-closed: cannot verify permissions (ADAP-SEC-0011)
      log.warn(
          "Permission verification unavailable for plugin {}: Redis miss and BC-02 fetch failed",
          pluginId);
      meterRegistry.counter(METRIC_UNAVAILABLE, "pluginId", pluginId).increment();

      Map<String, Object> details = new LinkedHashMap<>();
      details.put("pluginId", pluginId);
      details.put("errorCode", ERROR_CODE_PERMISSION_UNAVAILABLE);

      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          503,
          "Service Unavailable",
          "Unable to verify plugin permissions",
          details);
      return;
    }

    if (!result.isGranted()) {
      // Permission was in JWT but NOT in manifest → revoked (ADAP-SEC-0010)
      log.warn(
          "Permission denied for plugin {}: required={}, manifest check failed",
          pluginId,
          requiredPermission);
      meterRegistry
          .counter(METRIC_DENIED, "pluginId", pluginId, "errorCode", ERROR_CODE_PERMISSION_REVOKED)
          .increment();

      Map<String, Object> details = new LinkedHashMap<>();
      details.put("pluginId", pluginId);
      details.put("requiredPermission", requiredPermission);
      details.put("errorCode", ERROR_CODE_PERMISSION_REVOKED);

      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          403,
          "Forbidden",
          String.format("Permission '%s' has been revoked", requiredPermission),
          details);
      return;
    }

    // Cache hit metric — if we got here via cache, the service handled it
    meterRegistry.counter(METRIC_CACHE_HIT, "pluginId", pluginId).increment();

    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return !path.startsWith(GATEWAY_PREFIX);
  }

  /**
   * Resolve required permission from route mapping configuration — delegates to {@link
   * PermissionIntersectionService}.
   */
  String resolveRequiredPermission(String path, String httpMethod) {
    return intersectionService.resolveRequiredPermission(path, httpMethod);
  }

  private String extractShortPluginId(String fullPluginId) {
    if (fullPluginId == null) {
      return "unknown";
    }
    int lastDot = fullPluginId.lastIndexOf('.');
    return lastDot >= 0 ? fullPluginId.substring(lastDot + 1) : fullPluginId;
  }

  private Map<String, Object> buildDetails(
      PluginSecurityContext pluginContext, String requiredPermission) {
    Map<String, Object> details = new LinkedHashMap<>();
    if (pluginContext != null) {
      details.put("pluginId", pluginContext.pluginId());
      if (requiredPermission != null) {
        details.put("requiredPermission", requiredPermission);
      }
    }
    return details;
  }
}
