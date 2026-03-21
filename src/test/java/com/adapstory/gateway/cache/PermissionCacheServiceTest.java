package com.adapstory.gateway.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.client.PermissionFetchClient;
import com.adapstory.gateway.config.GatewayProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@DisplayName("PermissionCacheService")
class PermissionCacheServiceTest {

  private PermissionCacheService cacheService;
  private StringRedisTemplate redisTemplate;
  private ValueOperations<String, String> valueOperations;
  private SimpleMeterRegistry meterRegistry;
  private PermissionFetchClient permissionFetchClient;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    redisTemplate = mock(StringRedisTemplate.class);
    valueOperations = mock(ValueOperations.class);
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    meterRegistry = new SimpleMeterRegistry();
    permissionFetchClient = mock(PermissionFetchClient.class);

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"));

    cacheService =
        new PermissionCacheService(
            redisTemplate, properties, new ObjectMapper(), meterRegistry, permissionFetchClient);
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
      Optional<List<String>> result = cacheService.getCachedPermissions("test-plugin");

      // Assert
      assertThat(result).isPresent();
      assertThat(result.get()).containsExactly("content.read", "submission.read");
    }

    @Test
    @DisplayName("Cache miss returns empty Optional")
    void cacheMiss_returnsEmpty() {
      // Arrange
      when(valueOperations.get("plugin:permissions:test-plugin")).thenReturn(null);

      // Act
      Optional<List<String>> result = cacheService.getCachedPermissions("test-plugin");

      // Assert
      assertThat(result).isEmpty();
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
  @DisplayName("BC-02 fetch and cache (SEC-3.2)")
  class FetchAndCache {

    @Test
    @DisplayName("should fetch from BC-02 and cache on success")
    void should_fetchAndCache_on_success() {
      // Arrange
      when(permissionFetchClient.fetchPermissions("test-plugin"))
          .thenReturn(Optional.of(List.of("content.read", "grade.write")));

      // Act
      Optional<List<String>> result = cacheService.fetchAndCachePermissions("test-plugin");

      // Assert
      assertThat(result).isPresent();
      assertThat(result.get()).containsExactly("content.read", "grade.write");
      verify(valueOperations)
          .set(
              eq("plugin:permissions:test-plugin"),
              eq("content.read,grade.write"),
              eq(Duration.ofMinutes(5)));
    }

    @Test
    @DisplayName("should return empty Optional and cache negative result when BC-02 unavailable")
    void should_returnEmpty_when_bc02Unavailable() {
      // Arrange
      when(permissionFetchClient.fetchPermissions("test-plugin")).thenReturn(Optional.empty());

      // Act
      Optional<List<String>> result = cacheService.fetchAndCachePermissions("test-plugin");

      // Assert
      assertThat(result).isEmpty();
      // Negative cache sentinel should be stored with short TTL (30s)
      verify(valueOperations)
          .set(
              eq("plugin:permissions:test-plugin"),
              eq("__UNAVAILABLE__"),
              eq(Duration.ofSeconds(30)));
    }

    @Test
    @DisplayName("should skip BC-02 call when negative cache sentinel is active (H-1 fix)")
    void should_skipBc02_when_negativeCacheActive() {
      // Arrange — negative sentinel in Redis
      when(valueOperations.get("plugin:permissions:test-plugin")).thenReturn("__UNAVAILABLE__");

      // Act
      Optional<List<String>> result = cacheService.fetchAndCachePermissions("test-plugin");

      // Assert — BC-02 NOT called, returns empty
      assertThat(result).isEmpty();
      verify(permissionFetchClient, never()).fetchPermissions(anyString());
    }

    @Test
    @DisplayName("should call BC-02 when no negative sentinel exists")
    void should_callBc02_when_noNegativeSentinel() {
      // Arrange — no sentinel in Redis
      when(valueOperations.get("plugin:permissions:test-plugin")).thenReturn(null);
      when(permissionFetchClient.fetchPermissions("test-plugin"))
          .thenReturn(Optional.of(List.of("content.read")));

      // Act
      Optional<List<String>> result = cacheService.fetchAndCachePermissions("test-plugin");

      // Assert
      assertThat(result).isPresent();
      verify(permissionFetchClient).fetchPermissions("test-plugin");
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

    @Test
    @DisplayName("should increment Micrometer counter tagged by pluginId on valid event (M-3)")
    void should_incrementCounter_on_validRevocationEvent() {
      // Arrange
      when(valueOperations.setIfAbsent(anyString(), anyString(), any(Duration.class)))
          .thenReturn(true);

      // Act
      cacheService.onPluginPermissionsRevoked(VALID_REVOCATION_EVENT, null, null);

      // Assert
      double count =
          meterRegistry
              .counter("plugin.permissions.revoked.count", "pluginId", "adapstory.assessment.quiz")
              .count();
      assertThat(count).isEqualTo(1.0);
    }

    @Nested
    @DisplayName("Idempotency")
    class Idempotency {

      @Test
      @DisplayName("should skip duplicate event with same ce-id (AC #3)")
      void should_skipDuplicateEvent() {
        // Arrange — first call returns false (key already exists)
        when(valueOperations.setIfAbsent(
                eq("revoked-event-processed:ce-uuid-123"), eq("1"), eq(Duration.ofHours(24))))
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
                eq("revoked-event-processed:ce-uuid-123"), eq("1"), eq(Duration.ofHours(24))))
            .thenReturn(true);

        // Act
        cacheService.onPluginPermissionsRevoked(VALID_REVOCATION_EVENT, null, null);

        // Assert
        verify(redisTemplate).delete("plugin:permissions:adapstory.assessment.quiz");
      }

      @Test
      @DisplayName("should still invalidate when ce-id is absent (M-2 — idempotency bypassed)")
      void should_invalidateCache_when_ceIdAbsent() {
        // Arrange — event without "id" field
        String eventWithoutCeId =
            """
            {"specversion":"1.0",\
            "type":"com.adapstory.plugin.domain.event.PluginPermissionsRevoked.v1",\
            "source":"/bc02/plugins/adapstory.assessment.quiz",\
            "data":{"pluginId":"adapstory.assessment.quiz",\
            "revokedPermissions":["write:learner"],\
            "currentPermissions":["read:data_model"]}}""";

        // Act
        cacheService.onPluginPermissionsRevoked(eventWithoutCeId, null, null);

        // Assert — invalidation still happens (fail-open for cache invalidation)
        verify(redisTemplate).delete("plugin:permissions:adapstory.assessment.quiz");
        // No dedup key should be set
        verify(valueOperations, never()).setIfAbsent(anyString(), anyString(), any(Duration.class));
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

      @Test
      @DisplayName("should rethrow transient Redis error for Spring Kafka retry (H-1)")
      void should_rethrowTransientRedisError() {
        // Arrange — Redis is down during dedup check
        when(valueOperations.setIfAbsent(anyString(), anyString(), any(Duration.class)))
            .thenThrow(new RedisConnectionFailureException("Connection refused"));

        // Act & Assert — exception propagates to Spring Kafka error handler
        assertThatThrownBy(
                () -> cacheService.onPluginPermissionsRevoked(VALID_REVOCATION_EVENT, null, null))
            .isInstanceOf(RedisConnectionFailureException.class);
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

    @Test
    @DisplayName("returns null for invalid pluginId format (M-2 — path traversal)")
    void extractPluginId_invalidFormat() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"pluginId\":\"../../etc/passwd\"}");

      // Act & Assert
      assertThat(cacheService.extractPluginIdFromData(data)).isNull();
    }

    @Test
    @DisplayName("returns null for blank pluginId value (M-2)")
    void extractPluginId_blank() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"pluginId\":\" \"}");

      // Act & Assert
      assertThat(cacheService.extractPluginIdFromData(data)).isNull();
    }
  }
}
