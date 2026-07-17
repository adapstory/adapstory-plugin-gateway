package com.adapstory.gateway.routing;

import io.micrometer.core.instrument.MeterRegistry;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/** Redis session-to-pod mapping shared by all Plugin Gateway replicas. */
@Component
final class RedisMcpSessionAffinityStore implements McpSessionAffinityStore {

  private static final String FAILURE_METRIC =
      "plugin_gateway_mcp_session_affinity_store_failures_total";

  private final StringRedisTemplate redisTemplate;
  private final MeterRegistry meterRegistry;
  private final String keyPrefix;

  RedisMcpSessionAffinityStore(
      StringRedisTemplate redisTemplate,
      MeterRegistry meterRegistry,
      @Value("${gateway.mcp.session-affinity-redis-key-prefix:gateway:mcp-session-affinity:v1:}")
          String keyPrefix) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.meterRegistry = Objects.requireNonNull(meterRegistry, "meterRegistry must not be null");
    if (keyPrefix == null
        || keyPrefix.isBlank()
        || keyPrefix.length() > 128
        || keyPrefix.chars().anyMatch(Character::isWhitespace)) {
      throw new IllegalArgumentException("Redis session affinity key prefix is not canonical");
    }
    this.keyPrefix = keyPrefix;
  }

  @Override
  public Optional<URI> findAndRefresh(McpSessionAffinityKey key, Duration ttl) {
    validateTtl(ttl);
    try {
      String value = redisTemplate.opsForValue().getAndExpire(key(key), ttl);
      if (value == null) {
        return Optional.empty();
      }
      try {
        return Optional.of(URI.create(value));
      } catch (IllegalArgumentException exception) {
        redisTemplate.delete(key(key));
        throw failure("read", "shared MCP session affinity is corrupt", exception);
      }
    } catch (McpSessionAffinityStoreException exception) {
      throw exception;
    } catch (RuntimeException exception) {
      throw failure("read", "shared MCP session affinity is unavailable", exception);
    }
  }

  @Override
  public void bind(McpSessionAffinityKey key, URI backendEndpoint, Duration ttl) {
    Objects.requireNonNull(backendEndpoint, "backendEndpoint must not be null");
    validateTtl(ttl);
    try {
      String redisKey = key(key);
      String value = backendEndpoint.toASCIIString();
      if (Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(redisKey, value, ttl))) {
        return;
      }
      String existing = redisTemplate.opsForValue().get(redisKey);
      if (!value.equals(existing)) {
        throw failure("write", "MCP session identifier collision", null);
      }
      redisTemplate.expire(redisKey, ttl);
    } catch (McpSessionAffinityStoreException exception) {
      throw exception;
    } catch (RuntimeException exception) {
      throw failure("write", "shared MCP session affinity is unavailable", exception);
    }
  }

  @Override
  public void delete(McpSessionAffinityKey key) {
    try {
      redisTemplate.delete(key(key));
    } catch (RuntimeException exception) {
      throw failure("delete", "shared MCP session affinity is unavailable", exception);
    }
  }

  private McpSessionAffinityStoreException failure(
      String operation, String message, Throwable cause) {
    meterRegistry.counter(FAILURE_METRIC, "operation", operation).increment();
    return cause == null
        ? new McpSessionAffinityStoreException(message)
        : new McpSessionAffinityStoreException(message, cause);
  }

  private String key(McpSessionAffinityKey key) {
    String material = key.tenantId() + '\u0000' + key.routeSlug() + '\u0000' + key.sessionId();
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8));
      return keyPrefix + HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static void validateTtl(Duration ttl) {
    if (ttl == null || ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("MCP session affinity TTL must be positive");
    }
  }
}
