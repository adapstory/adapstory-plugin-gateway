package com.adapstory.gateway.cache;

import com.adapstory.gateway.config.GatewayProperties;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Redis-кеш для результатов проверки установки плагинов.
 *
 * <p>Ключ: {@code plugin-gateway:installed:{pluginId}:{tenantId}} → "true" | "false" |
 * "__UNAVAILABLE__". TTL конфигурируется через {@code gateway.installed-cache.*}. При cache miss
 * вызывает {@link InstalledPluginFetchClient} и кеширует результат. Negative cache sentinel
 * предотвращает thundering herd при недоступности BC-02. Вызывающий код обязан fail-close, если
 * получает sentinel как Optional.empty().
 */
@Service
public class InstalledPluginCacheService {

  private static final Logger log = LoggerFactory.getLogger(InstalledPluginCacheService.class);
  private static final String KEY_PREFIX = "plugin-gateway:installed:";
  private static final String NEGATIVE_CACHE_SENTINEL = "__UNAVAILABLE__";

  /** Safe characters for cache key components (no colon to prevent key ambiguity). */
  private static final Pattern SAFE_KEY_PART = Pattern.compile("^[a-zA-Z0-9._-]+$");

  private final InstalledPluginStatusCacheStore cacheStore;
  private final InstalledPluginStatusSource statusSource;
  private final Duration cacheTtl;
  private final Duration negativeCacheTtl;

  public InstalledPluginCacheService(
      InstalledPluginStatusCacheStore cacheStore,
      InstalledPluginStatusSource statusSource,
      GatewayProperties properties) {
    this.cacheStore = Objects.requireNonNull(cacheStore, "cacheStore must not be null");
    this.statusSource = Objects.requireNonNull(statusSource, "statusSource must not be null");
    Objects.requireNonNull(properties, "properties must not be null");
    var ic = properties.installedCache();
    this.cacheTtl = Duration.ofMinutes(ic != null ? ic.ttlMinutes() : 5);
    this.negativeCacheTtl = Duration.ofSeconds(ic != null ? ic.negativeTtlSeconds() : 30);
  }

  /**
   * Проверяет, установлен ли плагин для тенанта. Использует Redis cache-aside.
   *
   * @param pluginId идентификатор плагина
   * @param tenantId идентификатор тенанта
   * @param onCacheHit callback to increment cache-hit metric (nullable)
   * @param onCacheMiss callback to increment cache-miss metric (nullable)
   * @return Optional.of(true/false) при наличии данных, Optional.empty() если verification
   *     unavailable и вызывающий код должен fail-close
   */
  public Optional<Boolean> isInstalled(String pluginId, String tenantId) {
    return isInstalled(pluginId, tenantId, null, null);
  }

  /** Проверяет установку с callback-ами для метрик. */
  public Optional<Boolean> isInstalled(
      String pluginId, String tenantId, Runnable onCacheHit, Runnable onCacheMiss) {
    String key = buildKey(pluginId, tenantId);

    try {
      String cached = cacheStore.find(key).orElse(null);
      if (cached != null) {
        if (NEGATIVE_CACHE_SENTINEL.equals(cached)) {
          log.debug(
              "Negative cache hit for installed check: pluginId={}, tenantId={}",
              pluginId,
              tenantId);
          return Optional.empty();
        }
        log.debug("Cache hit for installed check: pluginId={}, tenantId={}", pluginId, tenantId);
        if (onCacheHit != null) onCacheHit.run();
        return Optional.of("true".equals(cached));
      }
    } catch (Exception e) {
      log.warn("Redis read error for installed check: {}", e.getMessage());
    }

    // Cache miss — fetch from BC-02
    if (onCacheMiss != null) onCacheMiss.run();
    Optional<Boolean> result = statusSource.fetchInstalledStatus(pluginId, tenantId);

    if (result.isPresent()) {
      // H-6: Both true and false from BC-02 are authoritative responses — use full cacheTtl.
      // negativeCacheTtl is reserved only for __UNAVAILABLE__ sentinel (BC-02 unreachable).
      cacheResult(key, result.get().toString(), cacheTtl);
    } else {
      // BC-02 unavailable — cache negative sentinel to prevent thundering herd
      cacheResult(key, NEGATIVE_CACHE_SENTINEL, negativeCacheTtl);
    }

    return result;
  }

  /**
   * Инвалидирует кеш для конкретного плагина+тенанта.
   *
   * @param pluginId идентификатор плагина
   * @param tenantId идентификатор тенанта
   */
  public void evict(String pluginId, String tenantId) {
    try {
      cacheStore.delete(buildKey(pluginId, tenantId));
    } catch (Exception e) {
      log.warn("Redis delete error for installed check eviction: {}", e.getMessage());
    }
  }

  private void cacheResult(String key, String value, Duration ttl) {
    try {
      cacheStore.put(key, value, ttl);
    } catch (Exception e) {
      log.warn("Redis write error for installed check: {}", e.getMessage());
    }
  }

  private static String buildKey(String pluginId, String tenantId) {
    Objects.requireNonNull(pluginId, "pluginId must not be null");
    Objects.requireNonNull(tenantId, "tenantId must not be null");
    if (!SAFE_KEY_PART.matcher(pluginId).matches()) {
      throw new IllegalArgumentException(
          "pluginId contains unsafe characters for cache key: " + pluginId);
    }
    if (!SAFE_KEY_PART.matcher(tenantId).matches()) {
      throw new IllegalArgumentException(
          "tenantId contains unsafe characters for cache key: " + tenantId);
    }
    return KEY_PREFIX + pluginId + ":" + tenantId;
  }
}
