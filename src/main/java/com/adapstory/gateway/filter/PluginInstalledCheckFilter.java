package com.adapstory.gateway.filter;

import com.adapstory.gateway.cache.InstalledPluginCacheService;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Фильтр проверки установки плагина для тенанта перед маршрутизацией запроса.
 *
 * <p>Порядок выполнения: после PluginAuthFilter (-100), перед PermissionEnforcementFilter (-90).
 * Извлекает pluginId и tenantId из PluginSecurityContext (установленного PluginAuthFilter). Проверяет
 * Redis cache → BC-02 REST API при miss. Возвращает 404 PLUGIN_NOT_INSTALLED если плагин не
 * установлен для тенанта.
 *
 * <p>Resilience: при недоступности BC-02 и Redis — fail-open с warning log (не блокирует трафик).
 */
@Component
@Order(-95)
public class PluginInstalledCheckFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(PluginInstalledCheckFilter.class);
  private static final String ERROR_CODE = "PLUGIN_NOT_INSTALLED";

  private final InstalledPluginCacheService cacheService;
  private final ObjectMapper objectMapper;
  private final Counter notInstalledCounter;

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
    this.notInstalledCounter =
        Counter.builder("plugin_gateway_not_installed_total")
            .description("Number of requests rejected due to plugin not installed for tenant")
            .register(Objects.requireNonNull(meterRegistry, "meterRegistry must not be null"));
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!(authentication instanceof PluginAuthenticationToken authToken)) {
      // No plugin auth context — skip check (will be caught by auth filter)
      filterChain.doFilter(request, response);
      return;
    }

    PluginSecurityContext ctx = (PluginSecurityContext) authToken.getPrincipal();
    String pluginId = ctx.pluginId();
    String tenantId = ctx.tenantId();

    if (pluginId == null || tenantId == null) {
      filterChain.doFilter(request, response);
      return;
    }

    Optional<Boolean> installed = cacheService.isInstalled(pluginId, tenantId);

    if (installed.isEmpty()) {
      // BC-02 unavailable — fail-open with warning
      log.warn(
          "Cannot verify plugin installation (BC-02 unavailable), allowing request: pluginId={}, tenantId={}",
          pluginId,
          tenantId);
      filterChain.doFilter(request, response);
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
          Map.of("plugin_id", pluginId, "tenant_id", tenantId, "error_code", ERROR_CODE));
      return;
    }

    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return path.startsWith("/actuator/") || path.startsWith("/internal/");
  }
}
