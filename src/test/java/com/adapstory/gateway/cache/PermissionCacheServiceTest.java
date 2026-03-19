package com.adapstory.gateway.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.config.GatewayProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@DisplayName("PermissionCacheService")
class PermissionCacheServiceTest {

  private PermissionCacheService cacheService;
  private StringRedisTemplate redisTemplate;
  private ValueOperations<String, String> valueOperations;
  private MeterRegistry meterRegistry;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    redisTemplate = mock(StringRedisTemplate.class);
    valueOperations = mock(ValueOperations.class);
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    meterRegistry = new SimpleMeterRegistry();

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null));

    cacheService =
        new PermissionCacheService(redisTemplate, properties, new ObjectMapper(), meterRegistry);
  }

  @Nested
  @DisplayName("Cache operations")
  class CacheOperations {

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
  }

  @Nested
  @DisplayName("PermissionCacheService — revocation event handling")
  class RevocationEventHandling {

    private static final String VALID_REVOCATION_EVENT =
        """
        {"specversion":"1.0","id":"ce-uuid-123",\
        "type":"com.adapstory.plugin.domain.event.PluginPermissionsRevoked.v1",\
        "source":"/bc02/plugins/adapstory.assessment.quiz",\
        "data":{"pluginId":"adapstory.assessment.quiz",\
        "revokedPermissions":["write:learner","read:analytics"],\
        "currentPermissions":["read:data_model"]}}""";

    @Test
    @DisplayName("should invalidate cache on valid revocation event (AC #2)")
    void should_invalidateCache_on_validRevocationEvent() {
      // Arrange
      when(valueOperations.setIfAbsent(anyString(), anyString(), any(Duration.class)))
          .thenReturn(true);

      // Act
      cacheService.onPluginPermissionsRevoked(VALID_REVOCATION_EVENT, null, null);

      // Assert
      verify(redisTemplate).delete("plugin:permissions:adapstory.assessment.quiz");
    }

    @Nested
    @DisplayName("Idempotency")
    class Idempotency {

      @Test
      @DisplayName("should skip duplicate event with same ce-id (AC #3)")
      void should_skipDuplicateEvent() {
        // Arrange — first call returns false (key already exists)
        when(valueOperations.setIfAbsent(
                eq("revoked-event-processed:ce-uuid-123"),
                eq("1"),
                eq(Duration.ofHours(24))))
            .thenReturn(false);

        // Act
        cacheService.onPluginPermissionsRevoked(VALID_REVOCATION_EVENT, null, null);

        // Assert — invalidate() NOT called
        verify(redisTemplate, never()).delete(anyString());
      }

      @Test
      @DisplayName("should process first event and set dedup key")
      void should_processFirstEvent_and_setDedupKey() {
        // Arrange
        when(valueOperations.setIfAbsent(
                eq("revoked-event-processed:ce-uuid-123"),
                eq("1"),
                eq(Duration.ofHours(24))))
            .thenReturn(true);

        // Act
        cacheService.onPluginPermissionsRevoked(VALID_REVOCATION_EVENT, null, null);

        // Assert
        verify(redisTemplate).delete("plugin:permissions:adapstory.assessment.quiz");
      }
    }

    @Nested
    @DisplayName("Error handling")
    class ErrorHandling {

      @Test
      @DisplayName("should not invalidate on malformed JSON")
      void should_notInvalidate_on_malformedJson() {
        // Act
        cacheService.onPluginPermissionsRevoked("not-valid-json{{{", null, null);

        // Assert
        verify(redisTemplate, never()).delete(anyString());
      }

      @Test
      @DisplayName("should not invalidate when pluginId is missing")
      void should_notInvalidate_when_pluginIdMissing() {
        // Arrange
        String eventWithoutPluginId =
            """
            {"specversion":"1.0","id":"ce-uuid-456",\
            "data":{"revokedPermissions":["read:analytics"]}}""";
        when(valueOperations.setIfAbsent(anyString(), anyString(), any(Duration.class)))
            .thenReturn(true);

        // Act
        cacheService.onPluginPermissionsRevoked(eventWithoutPluginId, null, null);

        // Assert
        verify(redisTemplate, never()).delete(anyString());
      }

      @Test
      @DisplayName("should reject oversized payload with >100 permissions")
      void should_rejectOversizedPayload() {
        // Arrange
        String permissions =
            IntStream.range(0, 101)
                .mapToObj(i -> "\"read:scope_" + i + "\"")
                .collect(Collectors.joining(",", "[", "]"));
        String oversizedEvent =
            "{\"specversion\":\"1.0\",\"id\":\"ce-uuid-789\","
                + "\"data\":{\"pluginId\":\"test-plugin\","
                + "\"revokedPermissions\":"
                + permissions
                + "}}";
        when(valueOperations.setIfAbsent(anyString(), anyString(), any(Duration.class)))
            .thenReturn(true);

        // Act
        cacheService.onPluginPermissionsRevoked(oversizedEvent, null, null);

        // Assert — invalidate() NOT called
        verify(redisTemplate, never()).delete(anyString());
      }
    }
  }

  @Nested
  @DisplayName("pluginId extraction")
  class PluginIdExtraction {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("extracts pluginId from camelCase key")
    void extractPluginId_camelCase() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"pluginId\":\"test-plugin\"}");

      // Act & Assert
      assertThat(cacheService.extractPluginIdFromData(data)).isEqualTo("test-plugin");
    }

    @Test
    @DisplayName("extracts pluginId from snake_case key")
    void extractPluginId_snakeCase() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"plugin_id\":\"test-plugin\"}");

      // Act & Assert
      assertThat(cacheService.extractPluginIdFromData(data)).isEqualTo("test-plugin");
    }

    @Test
    @DisplayName("returns null when pluginId missing")
    void extractPluginId_missing() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"other\":\"value\"}");

      // Act & Assert
      assertThat(cacheService.extractPluginIdFromData(data)).isNull();
    }
  }
}
