package com.adapstory.gateway.routing;

import com.adapstory.gateway.config.GatewayProperties;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/** Shared, deterministic stateful-session router for multi-replica Plugin Gateway. */
@Component
final class McpSessionAffinityRouter {

  private static final String MCP_PATH = "/mcp";

  private final McpSessionAffinityStore store;
  private final McpBackendAddressResolver addressResolver;
  private final Duration ttl;

  @Autowired
  McpSessionAffinityRouter(
      McpSessionAffinityStore store,
      McpBackendAddressResolver addressResolver,
      GatewayProperties properties) {
    this(store, addressResolver, Duration.ofSeconds(properties.mcp().sessionAffinityTtlSeconds()));
  }

  McpSessionAffinityRouter(
      McpSessionAffinityStore store, McpBackendAddressResolver addressResolver, Duration ttl) {
    if (ttl == null || ttl.isZero() || ttl.isNegative()) {
      throw new IllegalArgumentException("MCP session affinity TTL must be positive");
    }
    this.store = java.util.Objects.requireNonNull(store, "store must not be null");
    this.addressResolver =
        java.util.Objects.requireNonNull(addressResolver, "addressResolver must not be null");
    this.ttl = ttl;
  }

  McpSessionRoute resolve(
      URI headlessEndpoint, String tenantId, String routeSlug, String sessionId, String requestId) {
    List<URI> allowedEndpoints = resolveAllowedEndpoints(headlessEndpoint);
    if (sessionId == null) {
      String routingKey = requireRoutingKey(requestId, tenantId, routeSlug);
      return new McpSessionRoute(
          allowedEndpoints.get(stableIndex(routingKey, allowedEndpoints.size())), true);
    }

    McpSessionAffinityKey key;
    try {
      key = new McpSessionAffinityKey(tenantId, routeSlug, sessionId);
    } catch (IllegalArgumentException exception) {
      throw new McpSessionRoutingException(
          McpSessionRoutingException.Reason.INVALID_SESSION, exception);
    }
    URI mapped;
    try {
      mapped =
          store
              .findAndRefresh(key, ttl)
              .orElseThrow(
                  () ->
                      new McpSessionRoutingException(
                          McpSessionRoutingException.Reason.SESSION_NOT_FOUND));
    } catch (McpSessionRoutingException exception) {
      throw exception;
    } catch (RuntimeException exception) {
      throw unavailable(exception);
    }
    if (!allowedEndpoints.contains(mapped)) {
      try {
        store.delete(key);
      } catch (RuntimeException exception) {
        throw unavailable(exception);
      }
      throw new McpSessionRoutingException(McpSessionRoutingException.Reason.AFFINITY_UNAVAILABLE);
    }
    return new McpSessionRoute(mapped, false);
  }

  void bind(String tenantId, String routeSlug, String sessionId, URI backendEndpoint) {
    try {
      store.bind(new McpSessionAffinityKey(tenantId, routeSlug, sessionId), backendEndpoint, ttl);
    } catch (IllegalArgumentException exception) {
      throw new McpSessionRoutingException(
          McpSessionRoutingException.Reason.INVALID_SESSION, exception);
    } catch (RuntimeException exception) {
      throw unavailable(exception);
    }
  }

  void terminate(String tenantId, String routeSlug, String sessionId) {
    try {
      store.delete(new McpSessionAffinityKey(tenantId, routeSlug, sessionId));
    } catch (IllegalArgumentException exception) {
      throw new McpSessionRoutingException(
          McpSessionRoutingException.Reason.INVALID_SESSION, exception);
    } catch (RuntimeException exception) {
      throw unavailable(exception);
    }
  }

  private List<URI> resolveAllowedEndpoints(URI endpoint) {
    validateHeadlessEndpoint(endpoint);
    try {
      List<URI> resolved =
          addressResolver.resolve(endpoint.getHost()).stream()
              .map(address -> concreteEndpoint(endpoint, address))
              .distinct()
              .sorted(Comparator.comparing(URI::toString))
              .toList();
      if (resolved.isEmpty()) {
        throw new McpSessionRoutingException(
            McpSessionRoutingException.Reason.AFFINITY_UNAVAILABLE);
      }
      return resolved;
    } catch (UnknownHostException | IllegalArgumentException exception) {
      throw unavailable(exception);
    }
  }

  private static void validateHeadlessEndpoint(URI endpoint) {
    if (endpoint == null
        || !("http".equals(endpoint.getScheme()) || "https".equals(endpoint.getScheme()))
        || endpoint.getHost() == null
        || endpoint.getUserInfo() != null
        || endpoint.getQuery() != null
        || endpoint.getFragment() != null
        || !MCP_PATH.equals(endpoint.getPath())) {
      throw new McpSessionRoutingException(McpSessionRoutingException.Reason.AFFINITY_UNAVAILABLE);
    }
  }

  private static URI concreteEndpoint(URI template, InetAddress address) {
    try {
      return new URI(
          template.getScheme(),
          null,
          address.getHostAddress(),
          template.getPort(),
          template.getPath(),
          null,
          null);
    } catch (URISyntaxException exception) {
      throw new IllegalArgumentException("resolved MCP backend address is invalid", exception);
    }
  }

  private static String requireRoutingKey(String requestId, String tenantId, String routeSlug) {
    if (requestId != null && !requestId.isBlank()) {
      return requestId;
    }
    return tenantId + '\u0000' + routeSlug;
  }

  private static int stableIndex(String value, int bound) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      return Math.floorMod(ByteBuffer.wrap(digest).getInt(), bound);
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static McpSessionRoutingException unavailable(Throwable cause) {
    return new McpSessionRoutingException(
        McpSessionRoutingException.Reason.AFFINITY_UNAVAILABLE, cause);
  }
}
