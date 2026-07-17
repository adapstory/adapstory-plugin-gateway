package com.adapstory.gateway.mcpgrant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@DisplayName("Redis MCP grant store")
class RedisMcpGrantStoreTest {

  private StringRedisTemplate redis;
  private ValueOperations<String, String> values;
  private ObjectMapper objectMapper;
  private SimpleMeterRegistry meters;
  private RedisMcpGrantStore store;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    redis = mock(StringRedisTemplate.class);
    values = mock(ValueOperations.class);
    when(redis.opsForValue()).thenReturn(values);
    objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    meters = new SimpleMeterRegistry();
    store = new RedisMcpGrantStore(redis, objectMapper, meters, "gateway:mcp-grant:v1:");
  }

  @Test
  @DisplayName("stores one JSON value under a SHA-256 jti key with Redis TTL")
  void should_store_hashed_token_identifier_with_ttl() throws Exception {
    var authorization = authorization();
    var ttl = Duration.ofSeconds(90);
    var expectedKey = "gateway:mcp-grant:v1:" + sha256("sensitive-token-jti");
    when(values.setIfAbsent(expectedKey, objectMapper.writeValueAsString(authorization), ttl))
        .thenReturn(true);

    assertThat(store.putIfAbsent("sensitive-token-jti", authorization, ttl)).isTrue();

    verify(values).setIfAbsent(expectedKey, objectMapper.writeValueAsString(authorization), ttl);
  }

  @Test
  @DisplayName("round-trips a strict immutable authorization record")
  void should_deserialize_authorization() throws Exception {
    var authorization = authorization();
    when(values.get("gateway:mcp-grant:v1:" + sha256("token-jti")))
        .thenReturn(objectMapper.writeValueAsString(authorization));

    assertThat(store.find("token-jti")).contains(authorization);
  }

  @Test
  @DisplayName("preserves corrupt shared state as a fail-closed anti-rebind tombstone")
  void should_preserve_and_fail_closed_on_corrupt_json() {
    var key = "gateway:mcp-grant:v1:" + sha256("token-jti");
    when(values.get(key)).thenReturn("{not-json");

    assertThatThrownBy(() -> store.find("token-jti")).isInstanceOf(McpGrantStorageException.class);
    verify(redis, never()).delete(key);
  }

  @Test
  @DisplayName("wraps Redis failures without leaking the raw token identifier")
  void should_wrap_redis_failure_without_raw_jti() {
    when(values.get(anyString())).thenThrow(new IllegalStateException("redis down"));

    assertThatThrownBy(() -> store.find("sensitive-token-jti"))
        .isInstanceOf(McpGrantStorageException.class)
        .hasMessageNotContaining("sensitive-token-jti");
    assertThat(
            meters
                .get("plugin_gateway_mcp_grant_store_failures_total")
                .tag("operation", "read")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  @DisplayName("emits the bounded write failure metric without token labels")
  void should_measure_write_failure() {
    when(values.setIfAbsent(anyString(), anyString(), org.mockito.ArgumentMatchers.any()))
        .thenThrow(new IllegalStateException("redis down"));

    assertThatThrownBy(
            () -> store.putIfAbsent("sensitive-token-jti", authorization(), Duration.ofSeconds(30)))
        .isInstanceOf(McpGrantStorageException.class);
    var counter =
        meters
            .get("plugin_gateway_mcp_grant_store_failures_total")
            .tag("operation", "write")
            .counter();
    assertThat(counter.count()).isEqualTo(1.0);
    assertThat(counter.getId().getTags()).hasSize(1);
  }

  private static McpGrantAuthorization authorization() {
    return new McpGrantAuthorization(
        "tenant-123",
        "actor-456",
        Instant.parse("2026-07-16T12:02:00Z"),
        List.of(
            new ProviderBindingGrant(
                "knowledge.source.search",
                "ai-methodist",
                "search_methodology_rag",
                "2026.07.1",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "tenant-service-jwt",
                "CORE",
                "tenant",
                "available",
                Instant.parse("2026-07-16T12:00:00Z"),
                "Search the tenant methodology knowledge base. Use only for grounded sources.")));
  }

  private static String sha256(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException(exception);
    }
  }
}
