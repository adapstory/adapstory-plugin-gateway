package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@DisplayName("Redis MCP session affinity store")
class RedisMcpSessionAffinityStoreTest {

  private static final String PREFIX = "gateway:mcp-session-affinity:v1:";
  private static final Duration TTL = Duration.ofHours(24);
  private static final McpSessionAffinityKey KEY =
      new McpSessionAffinityKey("tenant-1", "ai-methodist", "secret-session-id");

  private StringRedisTemplate redis;
  private ValueOperations<String, String> values;
  private SimpleMeterRegistry meters;
  private RedisMcpSessionAffinityStore store;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    redis = mock(StringRedisTemplate.class);
    values = mock(ValueOperations.class);
    when(redis.opsForValue()).thenReturn(values);
    meters = new SimpleMeterRegistry();
    store = new RedisMcpSessionAffinityStore(redis, meters, PREFIX);
  }

  @Test
  @DisplayName("uses a hashed tenant-route-session key and refreshes TTL atomically on read")
  void should_hash_sensitive_key_and_refresh_ttl() {
    String redisKey = expectedRedisKey();
    URI endpoint = URI.create("http://10.42.0.8:8000/mcp");
    when(values.getAndExpire(redisKey, TTL)).thenReturn(endpoint.toASCIIString());

    assertThat(store.findAndRefresh(KEY, TTL)).contains(endpoint);

    verify(values).getAndExpire(redisKey, TTL);
    assertThat(redisKey).doesNotContain("tenant-1", "ai-methodist", "secret-session-id");
  }

  @Test
  @DisplayName("creates one immutable session binding with TTL")
  void should_bind_once_with_ttl() {
    String redisKey = expectedRedisKey();
    URI endpoint = URI.create("http://10.42.0.8:8000/mcp");
    when(values.setIfAbsent(redisKey, endpoint.toASCIIString(), TTL)).thenReturn(true);

    store.bind(KEY, endpoint, TTL);

    verify(values).setIfAbsent(redisKey, endpoint.toASCIIString(), TTL);
  }

  @Test
  @DisplayName("fails closed on a session collision instead of moving the session")
  void should_reject_backend_rebinding_collision() {
    String redisKey = expectedRedisKey();
    URI endpoint = URI.create("http://10.42.0.8:8000/mcp");
    when(values.setIfAbsent(redisKey, endpoint.toASCIIString(), TTL)).thenReturn(false);
    when(values.get(redisKey)).thenReturn("http://10.42.0.9:8000/mcp");

    assertThatThrownBy(() -> store.bind(KEY, endpoint, TTL))
        .isInstanceOf(McpSessionAffinityStoreException.class)
        .hasMessageNotContaining("secret-session-id");
    assertThat(
            meters
                .get("plugin_gateway_mcp_session_affinity_store_failures_total")
                .tag("operation", "write")
                .counter()
                .count())
        .isEqualTo(1.0);
  }

  @Test
  @DisplayName("wraps Redis failures without exposing session identifiers")
  void should_sanitize_shared_store_failure() {
    when(values.getAndExpire(anyString(), org.mockito.ArgumentMatchers.any()))
        .thenThrow(new IllegalStateException("redis down"));

    assertThatThrownBy(() -> store.findAndRefresh(KEY, TTL))
        .isInstanceOf(McpSessionAffinityStoreException.class)
        .hasMessageNotContaining("secret-session-id");
  }

  private static String expectedRedisKey() {
    String material = "tenant-1\u0000ai-methodist\u0000secret-session-id";
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8));
      return PREFIX + HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException(exception);
    }
  }
}
