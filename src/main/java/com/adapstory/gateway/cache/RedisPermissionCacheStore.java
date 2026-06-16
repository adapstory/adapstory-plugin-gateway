package com.adapstory.gateway.cache;

import java.time.Duration;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
final class RedisPermissionCacheStore implements PermissionCacheStore {

  private final StringRedisTemplate redisTemplate;

  RedisPermissionCacheStore(StringRedisTemplate redisTemplate) {
    this.redisTemplate = redisTemplate;
  }

  @Override
  public Optional<String> find(String key) {
    return Optional.ofNullable(redisTemplate.opsForValue().get(key));
  }

  @Override
  public void put(String key, String value, Duration ttl) {
    redisTemplate.opsForValue().set(key, value, ttl);
  }

  @Override
  public Boolean delete(String key) {
    return redisTemplate.delete(key);
  }
}
