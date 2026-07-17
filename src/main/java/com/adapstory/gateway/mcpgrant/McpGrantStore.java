package com.adapstory.gateway.mcpgrant;

import java.time.Duration;
import java.util.Optional;

/** Shared, token-bound grant persistence contract. */
public interface McpGrantStore {

  Optional<McpGrantAuthorization> find(String tokenId);

  boolean putIfAbsent(String tokenId, McpGrantAuthorization authorization, Duration ttl);
}
