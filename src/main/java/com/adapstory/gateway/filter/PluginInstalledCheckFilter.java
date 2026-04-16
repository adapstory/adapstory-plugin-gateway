package com.adapstory.gateway.filter;

import com.adapstory.gateway.cache.InstalledPluginCacheService;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/**
 * Фильтр проверки установки плагина для тенанта перед маршрутизацией запроса.
 *
 * <p>Порядок выполнения: после PluginAuthFilter (-100), перед PermissionEnforcementFilter (-90).
 * Извлекает pluginId и tenantId из PluginSecurityContext (установленного PluginAuthFilter).
 * Проверяет Redis cache → BC-02 REST API при miss. Возвращает 404 PLUGIN_NOT_INSTALLED если плагин
 * не установлен для тенанта.
 *
 * <p>Resilience: при недоступности BC-02, Redis или повреждённом verification state — fail-closed с
 * 503, чтобы gateway не пропускал трафик к неустановленным или непроверенным плагинам.
 */
@Component
public class PluginInstalledCheckFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(PluginInstalledCheckFilter.class);
  private static final String ERROR_CODE_NOT_INSTALLED = "PLUGIN_NOT_INSTALLED";
  private static final String ERROR_CODE_INSTALLATION_UNAVAILABLE = "ADAP-SEC-0011";

  private final InstalledPluginCacheService cacheService;
  private final ObjectMapper objectMapper;
  private final Counter notInstalledCounter;
  private final Counter unavailableCounter;
  private final Counter cacheHitCounter;
  private final Counter cacheMissCounter;

  /**
   * Создаёт фильтр проверки установки плагина.
   *
   * @param cacheService кеш-сервис для проверки установки
   * @param objectMapper Jackson ObjectMapper для сериализации ошибок
   * @param meterRegistry реестр метрик Micrometer
   */
  public PluginInstalledCheckFilter(
      InstalledPluginCacheService cacheService,
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry) {
    this.cacheService = Objects.requireNonNull(cacheService, "cacheService must not be null");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    Objects.requireNonNull(meterRegistry, "meterRegistry must not be null");
    this.notInstalledCounter =
        Counter.builder("plugin_gateway_not_installed_total")
            .description("Number of requests rejected due to plugin not installed for tenant")
            .register(meterRegistry);
    this.unavailableCounter =
        Counter.builder("plugin_gateway_installed_unavailable_total")
            .description(
                "Number of requests rejected because plugin installation could not be verified")
            .register(meterRegistry);
    this.cacheHitCounter =
        Counter.builder("plugin_gateway_installed_cache_hit_total")
            .description("Number of installed-check cache hits")
            .register(meterRegistry);
    this.cacheMissCounter =
        Counter.builder("plugin_gateway_installed_cache_miss_total")
            .description("Number of installed-check cache misses (BC-02 fetch)")
            .register(meterRegistry);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    PluginSecurityContext ctx =
        (PluginSecurityContext) request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);

    if (ctx == null) {
      // No plugin auth context — skip check (will be caught by auth filter)
      filterChain.doFilter(request, response);
      return;
    }

    String pluginId = ctx.pluginId();
    String tenantId = ctx.tenantId();

    if (pluginId == null || tenantId == null) {
      log.warn(
          "Plugin security context is incomplete, rejecting installed check: pluginId={}, tenantId={}",
          pluginId,
          tenantId);
      writeInstallationUnavailable(request, response, pluginId, tenantId);
      return;
    }

    Optional<Boolean> installed;
    try {
      installed =
          cacheService.isInstalled(
              pluginId, tenantId, cacheHitCounter::increment, cacheMissCounter::increment);
    } catch (IllegalArgumentException e) {
      log.warn(
          "Invalid key format for installed check, rejecting request: pluginId={}, tenantId={}, error={}",
          pluginId,
          tenantId,
          e.getMessage());
      writeInstallationUnavailable(request, response, pluginId, tenantId);
      return;
    }

    if (installed.isEmpty()) {
      log.warn(
          "Cannot verify plugin installation, rejecting request: pluginId={}, tenantId={}",
          pluginId,
          tenantId);
      writeInstallationUnavailable(request, response, pluginId, tenantId);
      return;
    }

    if (!installed.get()) {
      notInstalledCounter.increment();
      log.info(
          "Plugin not installed for tenant, rejecting: pluginId={}, tenantId={}",
          pluginId,
          tenantId);
      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          404,
          "Not Found",
          "Plugin is not installed for this tenant",
          Map.of(
              "plugin_id",
              pluginId,
              "tenant_id",
              tenantId,
              "error_code",
              ERROR_CODE_NOT_INSTALLED));
      return;
    }

    filterChain.doFilter(request, response);
  }

  private void writeInstallationUnavailable(
      HttpServletRequest request, HttpServletResponse response, String pluginId, String tenantId)
      throws IOException {
    unavailableCounter.increment();
    Map<String, Object> details = new LinkedHashMap<>();
    details.put("plugin_id", pluginId);
    details.put("tenant_id", tenantId);
    details.put("error_code", ERROR_CODE_INSTALLATION_UNAVAILABLE);
    GatewayErrorWriter.writeError(
        objectMapper,
        response,
        request,
        503,
        "Service Unavailable",
        "Unable to verify plugin installation",
        details);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return path.startsWith("/actuator/");
  }
}
