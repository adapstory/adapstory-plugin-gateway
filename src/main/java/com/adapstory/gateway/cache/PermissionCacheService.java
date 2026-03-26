package com.adapstory.gateway.cache;

import com.adapstory.gateway.client.PermissionFetchClient;
import com.adapstory.gateway.config.GatewayProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

/**
 * Кеш разрешений плагинов в Redis.
 *
 * <p>Ключ: plugin:permissions:{pluginId}, TTL = configurable (default 5 min). На промах кеша: fetch
 * из BC-02 REST API (Story SEC-3.2). Инвалидация через Kafka делегирована в {@link
 * com.adapstory.gateway.event.PermissionCacheInvalidationListener}.
 */
@Service
public class PermissionCacheService {

  private static final Logger log = LoggerFactory.getLogger(PermissionCacheService.class);
  private static final String PERMISSIONS_SEPARATOR = ",";
  private static final int MAX_REVOKED_PERMISSIONS = 100;
  private static final int MAX_SCOPE_LENGTH = 255;
  private static final Duration DEDUP_TTL = Duration.ofHours(24);
  private static final String DEDUP_KEY_PREFIX = "revoked-event-processed:";

  /** Negative cache TTL: prevents thundering herd when BC-02 is down (M-5). */
  private static final Duration NEGATIVE_CACHE_TTL = Duration.ofSeconds(30);

  private static final String NEGATIVE_CACHE_SENTINEL = "__UNAVAILABLE__";

  private final StringRedisTemplate redisTemplate;
  private final GatewayProperties properties;
  private final ObjectMapper objectMapper;
  private final PermissionFetchClient permissionFetchClient;

  public PermissionCacheService(
      StringRedisTemplate redisTemplate,
      GatewayProperties properties,
      ObjectMapper objectMapper,
      PermissionFetchClient permissionFetchClient) {
    this.redisTemplate = redisTemplate;
    this.properties = properties;
    this.objectMapper = objectMapper;
    this.permissionFetchClient = permissionFetchClient;
  }

  /**
   * Получает кешированные permissions плагина из Redis.
   *
   * @param pluginId идентификатор плагина
   * @return {@code Optional.of(permissions)} при cache hit, {@code Optional.empty()} при cache miss
   *     или negative cache hit (BC-02 unavailable sentinel)
   */
  public Optional<List<String>> getCachedPermissions(String pluginId) {
    PermissionFetchClient.validatePluginId(pluginId);
    String key = buildCacheKey(pluginId);
    String cached = redisTemplate.opsForValue().get(key);
    if (cached == null) {
      log.debug("Permission cache miss for plugin '{}'", pluginId);
      return Optional.empty();
    }
    if (NEGATIVE_CACHE_SENTINEL.equals(cached)) {
      log.debug("Negative cache hit for plugin '{}' (BC-02 was unavailable)", pluginId);
      return Optional.empty();
    }
    log.debug("Permission cache hit for plugin '{}'", pluginId);
    if (cached.isBlank()) {
      return Optional.of(List.of());
    }
    return Optional.of(List.of(cached.split(PERMISSIONS_SEPARATOR)));
  }

  /**
   * Кеширует permissions плагина в Redis.
   *
   * @param pluginId идентификатор плагина
   * @param permissions список разрешений
   */
  public void cachePermissions(String pluginId, List<String> permissions) {
    validatePermissionNames(permissions);
    String key = buildCacheKey(pluginId);
    String value = String.join(PERMISSIONS_SEPARATOR, permissions);
    Duration ttl = Duration.ofMinutes(properties.permissionCache().ttlMinutes());
    redisTemplate.opsForValue().set(key, value, ttl);
    log.debug("Cached permissions for plugin '{}': {}", pluginId, permissions);
  }

  /**
   * Инвалидирует кеш permissions плагина.
   *
   * @param pluginId идентификатор плагина
   */
  public void invalidate(String pluginId) {
    String key = buildCacheKey(pluginId);
    Boolean deleted = redisTemplate.delete(key);
    log.info("Invalidated permission cache for plugin '{}': deleted={}", pluginId, deleted);
  }

  /**
   * Запрашивает permissions из BC-02 REST API, кеширует результат в Redis.
   *
   * <p>Используется при промахе кеша вместо fallback на JWT claims (Story SEC-3.2). При сбое BC-02
   * или открытом circuit breaker возвращает {@code Optional.empty()} и записывает negative cache
   * (30s) для предотвращения thundering herd — вызывающий код реализует fail-closed (503
   * ADAP-SEC-0011).
   *
   * @param pluginId идентификатор плагина
   * @return {@code Optional<List<String>>} со scope-именами; {@code empty()} при сбое BC-02
   */
  public Optional<List<String>> fetchAndCachePermissions(String pluginId) {
    if (isNegativeCached(pluginId)) {
      log.debug("Negative cache active for plugin '{}', skipping BC-02 call", pluginId);
      return Optional.empty();
    }

    Optional<List<String>> fetched = permissionFetchClient.fetchPermissions(pluginId);
    if (fetched.isPresent()) {
      cachePermissions(pluginId, fetched.get());
    } else {
      cacheNegativeResult(pluginId);
    }
    return fetched;
  }

  // ── Event processing helpers (used by PermissionCacheInvalidationListener) ──

  /**
   * Парсит JSON event.
   *
   * @param message raw JSON string
   * @return parsed JsonNode tree
   * @throws JsonProcessingException при ошибке парсинга
   */
  public JsonNode parseEvent(String message) throws JsonProcessingException {
    return objectMapper.readTree(message);
  }

  /** Извлекает CloudEvents id из дерева. */
  public String extractCeId(JsonNode tree) {
    JsonNode idNode = tree.path("id");
    if (idNode.isMissingNode() || idNode.isNull()) {
      return null;
    }
    return idNode.asText();
  }

  /** Проверяет, обработано ли событие ранее (idempotency via Redis dedup key). */
  public boolean isDuplicateEvent(String ceId) {
    String dedupKey = DEDUP_KEY_PREFIX + ceId;
    Boolean isNew = redisTemplate.opsForValue().setIfAbsent(dedupKey, "1", DEDUP_TTL);
    return Boolean.FALSE.equals(isNew);
  }

  /** Валидирует payload события (revokedPermissions size и scope length). */
  public boolean validatePayload(JsonNode dataNode) {
    JsonNode revokedNode = dataNode.path("revokedPermissions");
    if (revokedNode.isArray() && revokedNode.size() > MAX_REVOKED_PERMISSIONS) {
      log.warn(
          "Rejected PluginPermissionsRevoked event: revokedPermissions count {} exceeds limit {}",
          revokedNode.size(),
          MAX_REVOKED_PERMISSIONS);
      return false;
    }
    if (revokedNode.isArray()) {
      for (JsonNode scope : revokedNode) {
        if (scope.isTextual() && scope.asText().length() > MAX_SCOPE_LENGTH) {
          log.warn(
              "Rejected PluginPermissionsRevoked event: scope length {} exceeds limit {}",
              scope.asText().length(),
              MAX_SCOPE_LENGTH);
          return false;
        }
      }
    }
    return true;
  }

  /** Извлекает pluginId из data-секции CloudEvent. */
  public String extractPluginIdFromData(JsonNode data) {
    JsonNode pluginIdNode = data.path("pluginId");
    if (pluginIdNode.isMissingNode()) {
      pluginIdNode = data.path("plugin_id");
    }
    if (pluginIdNode.isMissingNode()) {
      return null;
    }
    String value = pluginIdNode.asText();
    try {
      PermissionFetchClient.validatePluginId(value);
    } catch (IllegalArgumentException | NullPointerException e) {
      log.warn("Rejected PluginPermissionsRevoked event: invalid pluginId format '{}'", value);
      return null;
    }
    return value;
  }

  // ── Private helpers ──

  boolean isNegativeCached(String pluginId) {
    String key = buildCacheKey(pluginId);
    String cached = redisTemplate.opsForValue().get(key);
    return NEGATIVE_CACHE_SENTINEL.equals(cached);
  }

  private void cacheNegativeResult(String pluginId) {
    String key = buildCacheKey(pluginId);
    redisTemplate.opsForValue().set(key, NEGATIVE_CACHE_SENTINEL, NEGATIVE_CACHE_TTL);
    log.debug("Cached negative result for plugin '{}' (BC-02 unavailable, TTL=30s)", pluginId);
  }

  private static void validatePermissionNames(List<String> permissions) {
    for (String perm : permissions) {
      if (perm.contains(PERMISSIONS_SEPARATOR)) {
        throw new IllegalArgumentException(
            "Permission name must not contain separator '" + PERMISSIONS_SEPARATOR + "': " + perm);
      }
    }
  }

  private String buildCacheKey(String pluginId) {
    return properties.permissionCache().keyPrefix() + pluginId;
  }
}
