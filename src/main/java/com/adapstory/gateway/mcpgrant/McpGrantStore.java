package com.adapstory.gateway.mcpgrant;

import java.time.Duration;
import java.util.Optional;

/** Shared, token-bound grant persistence contract. */
public interface McpGrantStore {

  Optional<McpGrantAuthorization> find(String tokenId);

  boolean putIfAbsent(String tokenId, McpGrantAuthorization authorization, Duration ttl);

  /** Claims a command key for one exact token and authorization; false means conflicting replay. */
  boolean claimIdempotencyKey(
      String idempotencyKey, String tokenId, McpGrantAuthorization authorization, Duration ttl);
}
