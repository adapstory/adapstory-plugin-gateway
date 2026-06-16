package com.adapstory.gateway.cache;

import java.time.Duration;
import java.util.Optional;

interface PermissionCacheStore {

  Optional<String> find(String key);

  void put(String key, String value, Duration ttl);

  Boolean delete(String key);
}
