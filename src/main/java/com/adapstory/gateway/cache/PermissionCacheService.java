package com.adapstory.gateway.cache;

import com.adapstory.gateway.config.GatewayProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

/**
 * Кеш разрешений плагинов в Redis с инвалидацией через Kafka.
 *
 * <p>Ключ: plugin:{pluginId}:permissions, TTL = configurable (default 5 min). Kafka consumer:
 * PluginPermissionsChanged event → инвалидация записи кеша. На промах кеша: fetch из BC-02 REST API
 * (заглушка — будет реализована при интеграции).
 */
@Service
public class PermissionCacheService {

  private static final Logger log = LoggerFactory.getLogger(PermissionCacheService.class);
  private static final String PERMISSIONS_SEPARATOR = ",";

  private final StringRedisTemplate redisTemplate;
  private final GatewayProperties properties;
  private final ObjectMapper objectMapper;

  public PermissionCacheService(
      StringRedisTemplate redisTemplate, GatewayProperties properties, ObjectMapper objectMapper) {
    this.redisTemplate = redisTemplate;
    this.properties = properties;
    this.objectMapper = objectMapper;
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
   * Kafka consumer: invalidates cache when plugin permissions change. Event format expected:
   * CloudEvents 1.0 with data containing pluginId field.
   */
  @KafkaListener(topics = "plugin.permissions.changed", groupId = "plugin-gateway-permissions")
  public void onPluginPermissionsChanged(String message) {
    try {
      // Extract pluginId from CloudEvents payload
      // Simple JSON extraction — the event data contains {"pluginId": "..."}
      String pluginId = extractPluginIdFromEvent(message);
      if (pluginId != null) {
        invalidate(pluginId);
        log.info("Processed PluginPermissionsChanged event for plugin '{}'", pluginId);
      } else {
        log.warn("Could not extract pluginId from PluginPermissionsChanged event");
      }
    } catch (Exception ex) {
      log.error("Failed to process PluginPermissionsChanged event: {}", ex.getMessage());
    }
  }

  String extractPluginIdFromEvent(String message) {
    try {
      JsonNode tree = objectMapper.readTree(message);
      JsonNode data = tree.path("data");
      JsonNode pluginIdNode = data.path("pluginId");
      if (pluginIdNode.isMissingNode()) {
        pluginIdNode = data.path("plugin_id");
      }
      return pluginIdNode.isMissingNode() ? null : pluginIdNode.asText();
    } catch (Exception ex) {
      log.warn("Failed to parse PluginPermissionsChanged event JSON: {}", ex.getMessage());
      return null;
    }
  }

  private String buildCacheKey(String pluginId) {
    return properties.permissionCache().keyPrefix() + pluginId;
  }
}
