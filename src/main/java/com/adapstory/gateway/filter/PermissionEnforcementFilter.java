package com.adapstory.gateway.filter;

import com.adapstory.gateway.dto.PluginSecurityContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

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
  private static final String TAG_PLUGIN_ID = "pluginId";

  private final PermissionIntersectionService intersectionService;
  private final MeterRegistry meterRegistry;
  private final PermissionEnforcementResponseWriter responseWriter;

  public PermissionEnforcementFilter(
      PermissionIntersectionService intersectionService,
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry) {
    this.intersectionService = intersectionService;
    this.meterRegistry = meterRegistry;
    this.responseWriter = new PermissionEnforcementResponseWriter(objectMapper);
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
      responseWriter.writeMissingPermission(request, response, pluginContext);
      return;
    }

    List<String> jwtPermissions = pluginContext.permissions();
    PermissionIntersectionResult result =
        intersectionService.computeIntersection(pluginId, jwtPermissions, requiredPermission);

    if (result.isJwtMissing()) {
      log.warn(
          "Permission denied for plugin {}: required={}, jwt={}",
          pluginId,
          requiredPermission,
          jwtPermissions);
      meterRegistry
          .counter(METRIC_DENIED, TAG_PLUGIN_ID, pluginId, "errorCode", "JWT_MISSING")
          .increment();
      responseWriter.writeJwtDenied(request, response, pluginContext, requiredPermission);
      return;
    }

    if (result.isUnavailable()) {
      // Fail-closed: cannot verify permissions (ADAP-SEC-0011)
      log.warn(
          "Permission verification unavailable for plugin {}: Redis miss and BC-02 fetch failed",
          pluginId);
      meterRegistry.counter(METRIC_UNAVAILABLE, TAG_PLUGIN_ID, pluginId).increment();
      responseWriter.writeUnavailable(
          request, response, pluginId, ERROR_CODE_PERMISSION_UNAVAILABLE);
      return;
    }

    if (!result.isGranted()) {
      // Permission was in JWT but NOT in manifest → revoked (ADAP-SEC-0010)
      log.warn(
          "Permission denied for plugin {}: required={}, manifest check failed",
          pluginId,
          result.getRequiredPermission());
      meterRegistry
          .counter(
              METRIC_DENIED, TAG_PLUGIN_ID, pluginId, "errorCode", ERROR_CODE_PERMISSION_REVOKED)
          .increment();
      responseWriter.writeManifestDenied(
          request,
          response,
          pluginId,
          result.getRequiredPermission(),
          ERROR_CODE_PERMISSION_REVOKED);
      return;
    }

    // Cache hit metric — if we got here via cache, the service handled it
    meterRegistry.counter(METRIC_CACHE_HIT, TAG_PLUGIN_ID, pluginId).increment();

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
}
