package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Shared MCP session backend affinity")
class McpSessionAffinityRouterTest {

  private static final URI HEADLESS_ENDPOINT =
      URI.create("http://ai-methodist-mcp-headless.plugins.svc.cluster.local:8000/mcp");
  private static final Duration TTL = Duration.ofHours(24);

  @Test
  @DisplayName("binds a server session to one concrete pod across gateway replicas")
  void should_share_exact_backend_binding_across_router_instances() throws Exception {
    var store = new InMemoryStore();
    McpBackendAddressResolver resolver =
        host ->
            List.of(
                InetAddress.getByAddress(host, new byte[] {10, 42, 0, 8}),
                InetAddress.getByAddress(host, new byte[] {10, 42, 0, 9}));
    var firstGateway = new McpSessionAffinityRouter(store, resolver, TTL);
    var secondGateway = new McpSessionAffinityRouter(store, resolver, TTL);

    McpSessionRoute initial =
        firstGateway.resolve(HEADLESS_ENDPOINT, "tenant-1", "ai-methodist", null, "request-123");
    firstGateway.bind("tenant-1", "ai-methodist", "session-abc", initial.backendEndpoint());
    McpSessionRoute subsequent =
        secondGateway.resolve(
            HEADLESS_ENDPOINT, "tenant-1", "ai-methodist", "session-abc", "request-456");

    assertThat(initial.newSession()).isTrue();
    assertThat(subsequent.newSession()).isFalse();
    assertThat(subsequent.backendEndpoint()).isEqualTo(initial.backendEndpoint());
    assertThat(subsequent.backendEndpoint().getHost()).isIn("10.42.0.8", "10.42.0.9");
    assertThat(store.lastRefreshTtl).isEqualTo(TTL);
  }

  @Test
  @DisplayName("returns session-not-found rather than silently rebinding an unknown session")
  void should_fail_closed_when_session_mapping_is_missing() throws Exception {
    var router =
        new McpSessionAffinityRouter(
            new InMemoryStore(),
            host -> List.of(InetAddress.getByAddress(host, new byte[] {10, 42, 0, 8})),
            TTL);

    assertThatThrownBy(
            () ->
                router.resolve(
                    HEADLESS_ENDPOINT,
                    "tenant-1",
                    "ai-methodist",
                    "unknown-session",
                    "request-123"))
        .isInstanceOf(McpSessionRoutingException.class)
        .extracting(error -> ((McpSessionRoutingException) error).reason())
        .isEqualTo(McpSessionRoutingException.Reason.SESSION_NOT_FOUND);
  }

  @Test
  @DisplayName("rejects a forged or stale Redis endpoint outside current headless DNS")
  void should_reject_mapped_endpoint_outside_allowed_pods() throws Exception {
    var store = new InMemoryStore();
    var key = new McpSessionAffinityKey("tenant-1", "ai-methodist", "session-abc");
    store.values.put(key, URI.create("http://169.254.169.254:8000/mcp"));
    var router =
        new McpSessionAffinityRouter(
            store, host -> List.of(InetAddress.getByAddress(host, new byte[] {10, 42, 0, 8})), TTL);

    assertThatThrownBy(
            () ->
                router.resolve(
                    HEADLESS_ENDPOINT, "tenant-1", "ai-methodist", "session-abc", "request-123"))
        .isInstanceOf(McpSessionRoutingException.class)
        .extracting(error -> ((McpSessionRoutingException) error).reason())
        .isEqualTo(McpSessionRoutingException.Reason.AFFINITY_UNAVAILABLE);
    assertThat(store.values).doesNotContainKey(key);
  }

  private static final class InMemoryStore implements McpSessionAffinityStore {

    private final Map<McpSessionAffinityKey, URI> values = new HashMap<>();
    private Duration lastRefreshTtl;

    @Override
    public Optional<URI> findAndRefresh(McpSessionAffinityKey key, Duration ttl) {
      lastRefreshTtl = ttl;
      return Optional.ofNullable(values.get(key));
    }

    @Override
    public void bind(McpSessionAffinityKey key, URI backendEndpoint, Duration ttl) {
      URI existing = values.putIfAbsent(key, backendEndpoint);
      if (existing != null && !existing.equals(backendEndpoint)) {
        throw new IllegalStateException("session collision");
      }
    }

    @Override
    public void delete(McpSessionAffinityKey key) {
      values.remove(key);
    }
  }
}
