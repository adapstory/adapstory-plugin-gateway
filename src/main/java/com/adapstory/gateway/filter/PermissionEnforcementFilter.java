package com.adapstory.gateway.filter;

import com.adapstory.gateway.cache.PermissionCacheService;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Фильтр проверки разрешений плагина.
 *
 * <p>Извлекает требуемое разрешение из маппинга route→permission в конфигурации, проверяет наличие
 * этого разрешения в JWT claims плагина. При отсутствии возвращает 403 с Pattern 8 error format.
 */
@Component
@Order(2)
public class PermissionEnforcementFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(PermissionEnforcementFilter.class);
  private static final String GATEWAY_PREFIX = "/gateway/api/";

  private final GatewayProperties properties;
  private final ObjectMapper objectMapper;
  private final PermissionCacheService permissionCacheService;

  public PermissionEnforcementFilter(
      GatewayProperties properties,
      ObjectMapper objectMapper,
      PermissionCacheService permissionCacheService) {
    this.properties = properties;
    this.objectMapper = objectMapper;
    this.permissionCacheService = permissionCacheService;
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

    String requiredPermission = resolveRequiredPermission(path, method);
    if (requiredPermission == null) {
      log.warn("No permission mapping found for path={} method={}", path, method);
      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          403,
          "Forbidden",
          "No permission mapping configured for this route",
          buildDetails(pluginContext, null, pluginContext.permissions()));
      return;
    }

    // Use permission cache when available. On cache miss, fall back to JWT claims and re-cache.
    // Known limitation: after Kafka invalidation, the next request with the same JWT will re-cache
    // stale JWT claims. Proper fix: fetch fresh permissions from BC-02 REST API on cache miss
    // instead of falling back to JWT. Tracked as tech debt — see PermissionCacheService comment.
    List<String> effectivePermissions =
        permissionCacheService.getCachedPermissions(pluginContext.pluginId());
    if (effectivePermissions == null) {
      effectivePermissions = pluginContext.permissions();
      permissionCacheService.cachePermissions(pluginContext.pluginId(), effectivePermissions);
    }

    if (!effectivePermissions.contains(requiredPermission)) {
      String shortPluginId = extractShortPluginId(pluginContext.pluginId());
      log.info(
          "Permission denied for plugin '{}': required={}, granted={}",
          shortPluginId,
          requiredPermission,
          effectivePermissions);

      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          403,
          "Forbidden",
          String.format(
              "Plugin '%s' does not have permission '%s'", shortPluginId, requiredPermission),
          buildDetails(pluginContext, requiredPermission, effectivePermissions));
      return;
    }

    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return !path.startsWith(GATEWAY_PREFIX);
  }

  /**
   * Resolve required permission from route mapping configuration. Path format:
   * /gateway/api/{routeKey}/v1/... Extracts routeKey and maps HTTP method to permission.
   */
  String resolveRequiredPermission(String path, String httpMethod) {
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

  private String extractShortPluginId(String fullPluginId) {
    if (fullPluginId == null) {
      return "unknown";
    }
    int lastDot = fullPluginId.lastIndexOf('.');
    return lastDot >= 0 ? fullPluginId.substring(lastDot + 1) : fullPluginId;
  }

  private Map<String, Object> buildDetails(
      PluginSecurityContext pluginContext,
      String requiredPermission,
      List<String> effectivePermissions) {
    Map<String, Object> details = new LinkedHashMap<>();
    if (pluginContext != null) {
      details.put("pluginId", pluginContext.pluginId());
      if (requiredPermission != null) {
        details.put("requiredPermission", requiredPermission);
      }
      details.put("grantedPermissions", effectivePermissions);
    }
    return details;
  }
}
