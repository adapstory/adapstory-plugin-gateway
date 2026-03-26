package com.adapstory.gateway.event;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.cache.PermissionCacheService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;

/**
 * Kafka consumer: инвалидирует кеш permissions плагина при отзыве (Story SEC-3.1).
 *
 * <p>Принимает CloudEvents 1.0 с типом {@code PluginPermissionsRevoked}, выполняет idempotency
 * check через ce-id в Redis, валидирует payload и делегирует инвалидацию в {@link
 * PermissionCacheService}.
 */
@Component
public class PermissionCacheInvalidationListener {

  private static final Logger log =
      LoggerFactory.getLogger(PermissionCacheInvalidationListener.class);
  private static final String COUNTER_NAME = "plugin.permissions.revoked.count";

  private final PermissionCacheService cacheService;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;

  public PermissionCacheInvalidationListener(
      PermissionCacheService cacheService, ObjectMapper objectMapper, MeterRegistry meterRegistry) {
    this.cacheService = cacheService;
    this.objectMapper = objectMapper;
    this.meterRegistry = meterRegistry;
  }

  /**
   * Обрабатывает событие отзыва permissions плагина.
   *
   * <p>Error strategy: deserialization/parsing errors caught and skipped (fail-safe); transient
   * infrastructure errors rethrown for Spring Kafka retry via DefaultErrorHandler.
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
      setMdcFromHeaders(correlationId, requestId);

      JsonNode tree = objectMapper.readTree(message);

      String ceId = cacheService.extractCeId(tree);
      if (ceId == null) {
        log.warn(
            "Received PluginPermissionsRevoked event without ce-id, idempotency check skipped");
      } else if (cacheService.isDuplicateEvent(ceId)) {
        log.debug("Skipping duplicate revocation event ce-id={}", ceId);
        return;
      }

      JsonNode dataNode = tree.path("data");
      if (!cacheService.validatePayload(dataNode)) {
        return;
      }

      String pluginId = cacheService.extractPluginIdFromData(dataNode);
      if (pluginId != null) {
        cacheService.invalidate(pluginId);
        meterRegistry.counter(COUNTER_NAME, "pluginId", pluginId).increment();
        log.info(
            "Processed PluginPermissionsRevoked event for plugin '{}', revokedPermissions={}",
            pluginId,
            dataNode.path("revokedPermissions"));
      } else {
        log.warn("Could not extract pluginId from PluginPermissionsRevoked event");
      }
    } catch (JsonProcessingException ex) {
      log.warn("Malformed GLOBAL_PLUGIN_PERMISSIONS_REVOKED event: {}", ex.getMessage());
    } finally {
      restoreMdc(IntegrationHeaders.CORRELATION_ID, previousCorrelationId);
      restoreMdc(IntegrationHeaders.REQUEST_ID, previousRequestId);
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
}
