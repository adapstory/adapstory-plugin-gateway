package com.adapstory.gateway.cache;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.client.PermissionFetchClient;
import com.adapstory.gateway.config.GatewayProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Service;

/**
 * Кеш разрешений плагинов в Redis с инвалидацией через Kafka.
 *
 * <p>Ключ: plugin:permissions:{pluginId}, TTL = configurable (default 5 min). Kafka consumer:
 * PluginPermissionsRevoked event → инвалидация записи кеша (Story SEC-3.1). На промах кеша: fetch
 * из BC-02 REST API (Story SEC-3.2).
 */
@Service
public class PermissionCacheService {

  private static final Logger log = LoggerFactory.getLogger(PermissionCacheService.class);
  private static final String PERMISSIONS_SEPARATOR = ",";
  private static final int MAX_REVOKED_PERMISSIONS = 100;
  private static final int MAX_SCOPE_LENGTH = 255;
  private static final Duration DEDUP_TTL = Duration.ofHours(24);
  private static final String DEDUP_KEY_PREFIX = "revoked-event-processed:";
  private static final String COUNTER_NAME = "plugin.permissions.revoked.count";

  /** Negative cache TTL: prevents thundering herd when BC-02 is down (M-5). */
  private static final Duration NEGATIVE_CACHE_TTL = Duration.ofSeconds(30);

  private static final String NEGATIVE_CACHE_SENTINEL = "__UNAVAILABLE__";

  private final StringRedisTemplate redisTemplate;
  private final GatewayProperties properties;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;
  private final PermissionFetchClient permissionFetchClient;

  public PermissionCacheService(
      StringRedisTemplate redisTemplate,
      GatewayProperties properties,
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry,
      PermissionFetchClient permissionFetchClient) {
    this.redisTemplate = redisTemplate;
    this.properties = properties;
    this.objectMapper = objectMapper;
    this.meterRegistry = meterRegistry;
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
    // Check negative cache sentinel first to prevent thundering herd (H-1 review fix).
    // getCachedPermissions() returns Optional.empty() for both real miss and sentinel,
    // so we must check Redis directly before hitting BC-02.
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

  /**
   * Kafka consumer: invalidates cache when plugin permissions are revoked (Story SEC-3.1). Event
   * format: CloudEvents 1.0 with data containing pluginId and revokedPermissions fields. Idempotent
   * via ce-id deduplication in Redis (24h TTL).
   *
   * <p>Error strategy (per integration-rules.md): deserialization/parsing errors are caught and
   * skipped (fail-safe); transient infrastructure errors (Redis) are rethrown for Spring Kafka
   * retry via DefaultErrorHandler.
   */
  @KafkaListener(
      topics = "${gateway.kafka.topics.permission-revocation}",
      groupId = "plugin-gateway-permissions")
  public void onPluginPermissionsRevoked(
      @Payload String message,
      @Header(name = IntegrationHeaders.CORRELATION_ID, required = false) String correlationId,
      @Header(name = IntegrationHeaders.REQUEST_ID, required = false) String requestId) {
    String previousCorrelationId = MDC.get(IntegrationHeaders.CORRELATION_ID);
    String previousRequestId = MDC.get(IntegrationHeaders.REQUEST_ID);
    try {
      // Propagate tracing headers from Kafka into MDC (per monitoring-observability-regulation)
      setMdcFromHeaders(correlationId, requestId);

      JsonNode tree = parseEvent(message);

      // Idempotency: check ce-id deduplication
      String ceId = extractCeId(tree);
      if (ceId == null) {
        log.warn(
            "Received PluginPermissionsRevoked event without ce-id, idempotency check skipped");
      } else if (isDuplicateEvent(ceId)) {
        log.debug("Skipping duplicate revocation event ce-id={}", ceId);
        return;
      }

      // Validate payload
      JsonNode dataNode = tree.path("data");
      if (!validatePayload(dataNode)) {
        return;
      }

      String pluginId = extractPluginIdFromData(dataNode);
      if (pluginId != null) {
        invalidate(pluginId);
        meterRegistry.counter(COUNTER_NAME, "pluginId", pluginId).increment();
        log.info(
            "Processed PluginPermissionsRevoked event for plugin '{}', revokedPermissions={}",
            pluginId,
            dataNode.path("revokedPermissions"));
      } else {
        log.warn("Could not extract pluginId from PluginPermissionsRevoked event");
      }
    } catch (JsonProcessingException ex) {
      // Deserialization error — skip (fail-safe, no DLQ needed for cache invalidation)
      log.warn("Malformed GLOBAL_PLUGIN_PERMISSIONS_REVOKED event: {}", ex.getMessage());
    } finally {
      restoreMdc(IntegrationHeaders.CORRELATION_ID, previousCorrelationId);
      restoreMdc(IntegrationHeaders.REQUEST_ID, previousRequestId);
    }
  }

  /**
   * Парсит JSON event. Выделен в метод для разделения JsonProcessingException (parsing, skip) от
   * runtime exceptions (transient, rethrow for retry).
   */
  JsonNode parseEvent(String message) throws JsonProcessingException {
    return objectMapper.readTree(message);
  }

  String extractCeId(JsonNode tree) {
    JsonNode idNode = tree.path("id");
    if (idNode.isMissingNode() || idNode.isNull()) {
      return null;
    }
    return idNode.asText();
  }

  boolean isDuplicateEvent(String ceId) {
    String dedupKey = DEDUP_KEY_PREFIX + ceId;
    Boolean isNew = redisTemplate.opsForValue().setIfAbsent(dedupKey, "1", DEDUP_TTL);
    return Boolean.FALSE.equals(isNew);
  }

  boolean validatePayload(JsonNode dataNode) {
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

  String extractPluginIdFromData(JsonNode data) {
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

  /**
   * Проверяет наличие negative cache sentinel для pluginId.
   *
   * @param pluginId идентификатор плагина
   * @return {@code true} если в Redis хранится sentinel (BC-02 был недоступен)
   */
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

  private static void setMdcFromHeaders(String correlationId, String requestId) {
    if (correlationId != null) {
      MDC.put(IntegrationHeaders.CORRELATION_ID, correlationId);
    }
    if (requestId != null) {
      MDC.put(IntegrationHeaders.REQUEST_ID, requestId);
    }
  }

  private static void restoreMdc(String key, String previousValue) {
    if (previousValue != null) {
      MDC.put(key, previousValue);
    } else {
      MDC.remove(key);
    }
  }

  private String buildCacheKey(String pluginId) {
    return properties.permissionCache().keyPrefix() + pluginId;
  }
}
