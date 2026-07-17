package com.adapstory.gateway.mcpgrant;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
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

/** Redis implementation with hashed token identifiers and atomic create-only writes. */
@Component
final class RedisMcpGrantStore implements McpGrantStore {

  private final StringRedisTemplate redisTemplate;
  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;
  private final String keyPrefix;

  RedisMcpGrantStore(
      StringRedisTemplate redisTemplate,
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry,
      @Value("${gateway.mcp.grants.redis-key-prefix:gateway:mcp-grant:v1:}") String keyPrefix) {
    this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    this.meterRegistry = Objects.requireNonNull(meterRegistry, "meterRegistry must not be null");
    if (keyPrefix == null
        || keyPrefix.isBlank()
        || keyPrefix.length() > 128
        || keyPrefix.chars().anyMatch(Character::isWhitespace)) {
      throw new IllegalArgumentException("Redis grant key prefix is not canonical");
    }
    this.keyPrefix = keyPrefix;
  }

  @Override
  public Optional<McpGrantAuthorization> find(String tokenId) {
    String key = key(tokenId);
    try {
      String value = redisTemplate.opsForValue().get(key);
      if (value == null) {
        return Optional.empty();
      }
      try {
        return Optional.of(objectMapper.readValue(value, McpGrantAuthorization.class));
      } catch (JsonProcessingException exception) {
        throw storageFailure("read", "shared MCP authorization is corrupt", exception);
      }
    } catch (McpGrantStorageException exception) {
      throw exception;
    } catch (RuntimeException exception) {
      throw storageFailure("read", "shared MCP authorization is unavailable", exception);
    }
  }

  @Override
  public boolean putIfAbsent(String tokenId, McpGrantAuthorization authorization, Duration ttl) {
    Objects.requireNonNull(authorization, "authorization must not be null");
    if (ttl == null || ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("grant TTL must be positive");
    }
    try {
      String value = objectMapper.writeValueAsString(authorization);
      return Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(key(tokenId), value, ttl));
    } catch (JsonProcessingException | RuntimeException exception) {
      throw storageFailure("write", "shared MCP authorization is unavailable", exception);
    }
  }

  private McpGrantStorageException storageFailure(
      String operation, String message, Exception cause) {
    meterRegistry
        .counter("plugin_gateway_mcp_grant_store_failures_total", "operation", operation)
        .increment();
    return new McpGrantStorageException(message, cause);
  }

  private String key(String tokenId) {
    Objects.requireNonNull(tokenId, "tokenId must not be null");
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(tokenId.getBytes(StandardCharsets.UTF_8));
      return keyPrefix + HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
