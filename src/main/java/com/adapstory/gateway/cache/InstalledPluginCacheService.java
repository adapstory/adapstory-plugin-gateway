package com.adapstory.gateway.cache;

import com.adapstory.gateway.client.InstalledPluginFetchClient;
import com.adapstory.gateway.config.GatewayProperties;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/**
 * Redis-кеш для результатов проверки установки плагинов.
 *
 * <p>Ключ: {@code plugin-gateway:installed:{pluginId}:{tenantId}} → "true" | "false" |
 * "__UNAVAILABLE__". TTL конфигурируется через {@code gateway.installed-cache.*}. При cache miss
 * вызывает {@link InstalledPluginFetchClient} и кеширует результат. Negative cache sentinel
 * предотвращает thundering herd при недоступности BC-02.
 */
@Service
public class InstalledPluginCacheService {

  private static final Logger log = LoggerFactory.getLogger(InstalledPluginCacheService.class);
  private static final String KEY_PREFIX = "plugin-gateway:installed:";
  private static final String NEGATIVE_CACHE_SENTINEL = "__UNAVAILABLE__";

  /** Safe characters for cache key components (no colon to prevent key ambiguity). */
  private static final Pattern SAFE_KEY_PART = Pattern.compile("^[a-zA-Z0-9._-]+$");

  private final StringRedisTemplate redisTemplate;
  private final InstalledPluginFetchClient fetchClient;
  private final Duration cacheTtl;
  private final Duration negativeCacheTtl;

  public InstalledPluginCacheService(
      StringRedisTemplate redisTemplate,
      InstalledPluginFetchClient fetchClient,
      GatewayProperties properties) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.fetchClient = Objects.requireNonNull(fetchClient, "fetchClient must not be null");
    Objects.requireNonNull(properties, "properties must not be null");
    this.cacheTtl = Duration.ofMinutes(properties.installedCache().ttlMinutes());
    this.negativeCacheTtl = Duration.ofSeconds(properties.installedCache().negativeTtlSeconds());
  }

  /**
   * Проверяет, установлен ли плагин для тенанта. Использует Redis cache-aside.
   *
   * @param pluginId идентификатор плагина
   * @param tenantId идентификатор тенанта
   * @return Optional.of(true/false) при наличии данных, Optional.empty() при недоступности BC-02
   */
  /**
   * Проверяет, установлен ли плагин для тенанта. Использует Redis cache-aside.
   *
   * @param pluginId идентификатор плагина
   * @param tenantId идентификатор тенанта
   * @param cacheHit callback to increment cache-hit metric (nullable)
   * @param cacheMiss callback to increment cache-miss metric (nullable)
   * @return Optional.of(true/false) при наличии данных, Optional.empty() при недоступности BC-02
   */
  public Optional<Boolean> isInstalled(String pluginId, String tenantId) {
    return isInstalled(pluginId, tenantId, null, null);
  }

  /**
   * Проверяет установку с callback-ами для метрик.
   */
  public Optional<Boolean> isInstalled(
      String pluginId, String tenantId, Runnable onCacheHit, Runnable onCacheMiss) {
    String key = buildKey(pluginId, tenantId);

    try {
      String cached = redisTemplate.opsForValue().get(key);
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
    Optional<Boolean> result = fetchClient.fetchInstalledStatus(pluginId, tenantId);

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
      redisTemplate.delete(buildKey(pluginId, tenantId));
    } catch (Exception e) {
      log.warn("Redis delete error for installed check eviction: {}", e.getMessage());
    }
  }

  private void cacheResult(String key, String value, Duration ttl) {
    try {
      redisTemplate.opsForValue().set(key, value, ttl);
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
