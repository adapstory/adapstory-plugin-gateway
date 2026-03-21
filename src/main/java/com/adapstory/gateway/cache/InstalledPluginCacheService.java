package com.adapstory.gateway.cache;

import com.adapstory.gateway.client.InstalledPluginFetchClient;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/**
 * Redis-кеш для результатов проверки установки плагинов.
 *
 * <p>Ключ: {@code plugin-gateway:installed:{pluginId}:{tenantId}} → "true" | "false". TTL: 5 минут
 * (конфигурируемо). При cache miss вызывает {@link InstalledPluginFetchClient} и кеширует результат.
 */
@Service
public class InstalledPluginCacheService {

  private static final Logger log = LoggerFactory.getLogger(InstalledPluginCacheService.class);
  private static final String KEY_PREFIX = "plugin-gateway:installed:";
  private static final Duration CACHE_TTL = Duration.ofMinutes(5);
  private static final Duration NEGATIVE_CACHE_TTL = Duration.ofSeconds(30);

  private final StringRedisTemplate redisTemplate;
  private final InstalledPluginFetchClient fetchClient;

  public InstalledPluginCacheService(
      StringRedisTemplate redisTemplate, InstalledPluginFetchClient fetchClient) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.fetchClient = Objects.requireNonNull(fetchClient, "fetchClient must not be null");
  }

  /**
   * Проверяет, установлен ли плагин для тенанта. Использует Redis cache-aside.
   *
   * @param pluginId идентификатор плагина
   * @param tenantId идентификатор тенанта
   * @return Optional.of(true/false) при наличии данных, Optional.empty() при недоступности BC-02
   */
  public Optional<Boolean> isInstalled(String pluginId, String tenantId) {
    String key = buildKey(pluginId, tenantId);

    try {
      String cached = redisTemplate.opsForValue().get(key);
      if (cached != null) {
        log.debug("Cache hit for installed check: pluginId={}, tenantId={}", pluginId, tenantId);
        return Optional.of("true".equals(cached));
      }
    } catch (Exception e) {
      log.warn("Redis read error for installed check: {}", e.getMessage());
    }

    // Cache miss — fetch from BC-02
    Optional<Boolean> result = fetchClient.fetchInstalledStatus(pluginId, tenantId);

    result.ifPresent(
        installed -> {
          try {
            Duration ttl = installed ? CACHE_TTL : NEGATIVE_CACHE_TTL;
            redisTemplate.opsForValue().set(key, installed.toString(), ttl);
          } catch (Exception e) {
            log.warn("Redis write error for installed check: {}", e.getMessage());
          }
        });

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

  private static String buildKey(String pluginId, String tenantId) {
    return KEY_PREFIX + pluginId + ":" + tenantId;
  }
}
