package com.adapstory.gateway.credential;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import org.springframework.data.redis.core.StringRedisTemplate;

public final class RedisCredentialNonceStore implements CredentialNonceStore {

  private final StringRedisTemplate redis;
  private final Clock clock;
  private final String prefix;

  public RedisCredentialNonceStore(StringRedisTemplate redis, Clock clock, String prefix) {
    this.redis = Objects.requireNonNull(redis, "redis must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.prefix = Objects.requireNonNull(prefix, "prefix must not be null");
  }

  @Override
  public boolean consume(String nonce, Instant expiresAt) {
    Duration ttl = Duration.between(clock.instant(), expiresAt);
    if (ttl.isZero() || ttl.isNegative()) {
      return false;
    }
    String key = prefix + CanonicalCredentialJson.sha256(nonce);
    return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, "used", ttl));
  }
}
