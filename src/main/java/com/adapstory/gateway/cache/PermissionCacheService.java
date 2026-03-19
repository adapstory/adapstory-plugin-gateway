package com.adapstory.gateway.cache;

import com.adapstory.gateway.config.GatewayProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
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

  private final StringRedisTemplate redisTemplate;
  private final GatewayProperties properties;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;

  public PermissionCacheService(
      StringRedisTemplate redisTemplate,
      GatewayProperties properties,
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry) {
    this.redisTemplate = redisTemplate;
    this.properties = properties;
    this.objectMapper = objectMapper;
    this.meterRegistry = meterRegistry;
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
   * Kafka consumer: invalidates cache when plugin permissions are revoked (Story SEC-3.1). Event
   * format: CloudEvents 1.0 with data containing pluginId and revokedPermissions fields. Idempotent
   * via ce-id deduplication in Redis (24h TTL).
   */
  @KafkaListener(
      topics = "${gateway.kafka.topics.permission-revocation}",
      groupId = "plugin-gateway-permissions")
  public void onPluginPermissionsRevoked(String message) {
    String previousCorrelationId = MDC.get("correlation-id");
    String previousRequestId = MDC.get("request-id");
    try {
      JsonNode tree = objectMapper.readTree(message);

      // Extract correlation-id and request-id from CloudEvent extensions
      setMdcFromEvent(tree);

      // Idempotency: check ce-id deduplication
      String ceId = extractCeId(tree);
      if (ceId != null && isDuplicateEvent(ceId)) {
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
        Counter.builder("plugin.permissions.revoked.count")
            .tag("pluginId", pluginId)
            .register(meterRegistry)
            .increment();
        log.info(
            "Processed PluginPermissionsRevoked event for plugin '{}', revokedPermissions={}",
            pluginId,
            dataNode.path("revokedPermissions"));
      } else {
        log.warn("Could not extract pluginId from PluginPermissionsRevoked event");
      }
    } catch (Exception ex) {
      log.warn("Malformed GLOBAL_PLUGIN_PERMISSIONS_REVOKED event: {}", ex.getMessage());
    } finally {
      restoreMdc("correlation-id", previousCorrelationId);
      restoreMdc("request-id", previousRequestId);
    }
  }

  String extractCeId(JsonNode tree) {
    JsonNode idNode = tree.path("id");
    return idNode.isMissingNode() ? null : idNode.asText();
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

  private void setMdcFromEvent(JsonNode tree) {
    JsonNode correlationId = tree.path("correlationid");
    if (!correlationId.isMissingNode()) {
      MDC.put("correlation-id", correlationId.asText());
    }
    JsonNode requestId = tree.path("requestid");
    if (!requestId.isMissingNode()) {
      MDC.put("request-id", requestId.asText());
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
