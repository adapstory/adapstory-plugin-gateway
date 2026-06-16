package com.adapstory.gateway.cache;

import java.time.Duration;
import java.util.Optional;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
final class RedisInstalledPluginStatusCacheAdapter implements InstalledPluginStatusCacheStore {

  private final StringRedisTemplate redisTemplate;

  RedisInstalledPluginStatusCacheAdapter(StringRedisTemplate redisTemplate) {
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
  public void delete(String key) {
    redisTemplate.delete(key);
  }
}
