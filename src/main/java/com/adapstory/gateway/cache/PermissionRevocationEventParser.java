package com.adapstory.gateway.cache;

import com.adapstory.gateway.client.PermissionFetchClient;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Парсит и валидирует CloudEvents {@code PluginPermissionsRevoked}.
 *
 * <p>Извлечён из {@link PermissionCacheService} для разделения event-parsing и cache-операций.
 * Используется {@link com.adapstory.gateway.event.PermissionCacheInvalidationListener}.
 *
 * <p>Отвечает за:
 *
 * <ul>
 *   <li>Десериализацию JSON-сообщения ({@link #parseEvent(String)})
 *   <li>Извлечение CloudEvents id ({@link #extractCeId(JsonNode)})
 *   <li>Idempotency-проверку через Redis dedup key ({@link #isDuplicateEvent(String)})
 *   <li>Валидацию payload — размер и длина scope ({@link #validatePayload(JsonNode)})
 *   <li>Извлечение pluginId с fallback на snake_case ({@link #extractPluginIdFromData(JsonNode)})
 * </ul>
 */
@Component
public class PermissionRevocationEventParser {

  private static final Logger log = LoggerFactory.getLogger(PermissionRevocationEventParser.class);
  private static final int MAX_REVOKED_PERMISSIONS = 100;
  private static final int MAX_SCOPE_LENGTH = 255;
  private static final Duration DEDUP_TTL = Duration.ofHours(24);
  private static final String DEDUP_KEY_PREFIX = "revoked-event-processed:";

  private final StringRedisTemplate redisTemplate;
  private final ObjectMapper objectMapper;

  public PermissionRevocationEventParser(
      StringRedisTemplate redisTemplate, ObjectMapper objectMapper) {
    this.redisTemplate = redisTemplate;
    this.objectMapper = objectMapper;
  }

  /**
   * Парсит JSON event.
   *
   * @param message raw JSON string
   * @return parsed JsonNode tree
   * @throws JacksonException при ошибке парсинга
   */
  public JsonNode parseEvent(String message) throws JacksonException {
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
}
