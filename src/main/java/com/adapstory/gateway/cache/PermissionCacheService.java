package com.adapstory.gateway.cache;

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
 * <p>Ключ: plugin:{pluginId}:permissions, TTL = configurable (default 5 min). Kafka consumer:
 * PluginPermissionsRevoked event → инвалидация записи кеша (Story SEC-3.1). На промах кеша: fetch
 * из BC-02 REST API (заглушка — будет реализована при интеграции).
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
   * Get cached permissions for a plugin.
   *
   * @param pluginId full plugin identifier
   * @return cached permissions or null if not in cache
   */
  public List<String> getCachedPermissions(String pluginId) {
    String key = buildCacheKey(pluginId);
    String cached = redisTemplate.opsForValue().get(key);
    if (cached == null) {
      log.debug("Permission cache miss for plugin '{}'", pluginId);
      return null;
    }
    log.debug("Permission cache hit for plugin '{}'", pluginId);
    if (cached.isBlank()) {
      return List.of();
    }
    return List.of(cached.split(PERMISSIONS_SEPARATOR));
  }

  /**
   * Cache permissions for a plugin.
   *
   * @param pluginId full plugin identifier
   * @param permissions list of granted permissions
   */
  public void cachePermissions(String pluginId, List<String> permissions) {
    String key = buildCacheKey(pluginId);
    String value = String.join(PERMISSIONS_SEPARATOR, permissions);
    Duration ttl = Duration.ofMinutes(properties.permissionCache().ttlMinutes());
    redisTemplate.opsForValue().set(key, value, ttl);
    log.debug("Cached permissions for plugin '{}': {}", pluginId, permissions);
  }

  /**
   * Invalidate cached permissions for a plugin.
   *
   * @param pluginId full plugin identifier
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
   * или открытом circuit breaker возвращает {@code Optional.empty()} — вызывающий код реализует
   * fail-closed (503 ADAP-SEC-0011).
   *
   * @param pluginId идентификатор плагина
   * @return {@code Optional<List<String>>} со scope-именами; {@code empty()} при сбое BC-02
   */
  public Optional<List<String>> fetchAndCachePermissions(String pluginId) {
    Optional<List<String>> fetched = permissionFetchClient.fetchPermissions(pluginId);
    fetched.ifPresent(permissions -> cachePermissions(pluginId, permissions));
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
      @Header(name = "correlation-id", required = false) String correlationId,
      @Header(name = "request-id", required = false) String requestId) {
    String previousCorrelationId = MDC.get("correlation-id");
    String previousRequestId = MDC.get("request-id");
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
      restoreMdc("correlation-id", previousCorrelationId);
      restoreMdc("request-id", previousRequestId);
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
    return pluginIdNode.isMissingNode() ? null : pluginIdNode.asText();
  }

  private static void setMdcFromHeaders(String correlationId, String requestId) {
    if (correlationId != null) {
      MDC.put("correlation-id", correlationId);
    }
    if (requestId != null) {
      MDC.put("request-id", requestId);
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
