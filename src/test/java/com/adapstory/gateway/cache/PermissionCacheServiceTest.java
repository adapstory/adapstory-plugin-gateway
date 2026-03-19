package com.adapstory.gateway.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.config.GatewayProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

/** Тесты PermissionCacheService: cache hit, cache miss, Kafka invalidation. */
class PermissionCacheServiceTest {

  private PermissionCacheService cacheService;
  private StringRedisTemplate redisTemplate;
  private ValueOperations<String, String> valueOperations;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    redisTemplate = mock(StringRedisTemplate.class);
    valueOperations = mock(ValueOperations.class);
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null));

    cacheService = new PermissionCacheService(redisTemplate, properties, new ObjectMapper());
  }

  @Test
  @DisplayName("Cache hit returns cached permissions")
  void cacheHit_returnsCachedPermissions() {
    // Arrange
    when(valueOperations.get("plugin:permissions:test-plugin"))
        .thenReturn("content.read,submission.read");

    // Act
    List<String> result = cacheService.getCachedPermissions("test-plugin");

    // Assert
    assertThat(result).containsExactly("content.read", "submission.read");
  }

  @Test
  @DisplayName("Cache miss returns null")
  void cacheMiss_returnsNull() {
    // Arrange
    when(valueOperations.get("plugin:permissions:test-plugin")).thenReturn(null);

    // Act
    List<String> result = cacheService.getCachedPermissions("test-plugin");

    // Assert
    assertThat(result).isNull();
  }

  @Test
  @DisplayName("Cache permissions stores with correct TTL")
  void cachePermissions_storesWithTtl() {
    // Act
    cacheService.cachePermissions("test-plugin", List.of("content.read", "grade.write"));

    // Assert
    verify(valueOperations)
        .set(
            eq("plugin:permissions:test-plugin"),
            eq("content.read,grade.write"),
            eq(Duration.ofMinutes(5)));
  }

  @Test
  @DisplayName("Invalidate deletes cache entry")
  void invalidate_deletesCacheEntry() {
    // Act
    cacheService.invalidate("test-plugin");

    // Assert
    verify(redisTemplate).delete("plugin:permissions:test-plugin");
  }

  @Test
  @DisplayName("Kafka event triggers cache invalidation")
  void kafkaEvent_triggersCacheInvalidation() {
    // Arrange
    String event =
        """
                {"specversion":"1.0","type":"PluginPermissionsChanged",\
                "data":{"pluginId":"adapstory.education_module.ai-grader"}}""";

    // Act
    cacheService.onPluginPermissionsChanged(event);

    // Assert
    verify(redisTemplate).delete("plugin:permissions:adapstory.education_module.ai-grader");
  }

  @Test
  @DisplayName("Extract pluginId from event with plugin_id key")
  void extractPluginId_snakeCase() {
    String event =
        """
                {"data":{"plugin_id":"test-plugin"}}""";
    assertThat(cacheService.extractPluginIdFromEvent(event)).isEqualTo("test-plugin");
  }

  @Test
  @DisplayName("Extract pluginId from event with pluginId key")
  void extractPluginId_camelCase() {
    String event =
        """
                {"data":{"pluginId":"test-plugin"}}""";
    assertThat(cacheService.extractPluginIdFromEvent(event)).isEqualTo("test-plugin");
  }

  @Test
  @DisplayName("Extract pluginId returns null for invalid event")
  void extractPluginId_invalidEvent() {
    assertThat(cacheService.extractPluginIdFromEvent("invalid")).isNull();
  }
}
