package com.adapstory.gateway.routing;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

/** Shared storage contract that keeps a stateful MCP session on one concrete provider pod. */
interface McpSessionAffinityStore {

  Optional<URI> findAndRefresh(McpSessionAffinityKey key, Duration ttl);

  void bind(McpSessionAffinityKey key, URI backendEndpoint, Duration ttl);

  void delete(McpSessionAffinityKey key);
}
