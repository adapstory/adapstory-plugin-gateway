package com.adapstory.gateway.mcpgrant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayName("MCP grant service")
class McpGrantServiceTest {

  private static final Instant NOW = Instant.parse("2026-07-16T12:00:00Z");
  private static final String TENANT = "tenant-123";
  private static final String ACTOR = "actor-456";

  @Mock private McpGrantStore store;
  @Mock private ProviderBindingVerifier verifier;

  private McpGrantService service;

  @BeforeEach
  void setUp() {
    service =
        new McpGrantService(
            store,
            verifier,
            Clock.fixed(NOW, ZoneOffset.UTC),
            Duration.ofMinutes(5),
            Duration.ofSeconds(5),
            Duration.ofSeconds(60));
  }

  @Test
  @DisplayName("verifies all bindings once and stores one token-bound record")
  void should_register_exact_binding_set_atomically() {
    var token = token(NOW.plusSeconds(120));
    var bindings = List.of(binding());
    when(store.putIfAbsent(
            "token-jti",
            new McpGrantAuthorization(TENANT, ACTOR, token.expiresAt(), bindings),
            Duration.ofSeconds(180)))
        .thenReturn(true);

    service.register(token, TENANT, ACTOR, bindings);

    verify(verifier).verify(TENANT, ACTOR, bindings);
    verify(store)
        .putIfAbsent(
            "token-jti",
            new McpGrantAuthorization(TENANT, ACTOR, token.expiresAt(), bindings),
            Duration.ofSeconds(180));
  }

  @Test
  @DisplayName("rejects caller-controlled identity before lifecycle or Redis I/O")
  void should_reject_identity_mismatch_before_io() {
    var token = token(NOW.plusSeconds(120));

    assertThatThrownBy(() -> service.register(token, TENANT, "different-actor", List.of(binding())))
        .isInstanceOf(McpGrantRejectedException.class)
        .hasMessageContaining("identity");

    verify(verifier, never()).verify(TENANT, ACTOR, List.of(binding()));
    verify(store, never())
        .putIfAbsent(
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any());
  }

  @Test
  @DisplayName("rejects expired and nearly-expired exchanged access tokens")
  void should_reject_token_without_minimum_validity() {
    assertThatThrownBy(
            () -> service.register(token(NOW.plusSeconds(4)), TENANT, ACTOR, List.of(binding())))
        .isInstanceOf(McpGrantRejectedException.class)
        .hasMessageContaining("validity");
  }

  @Test
  @DisplayName("rejects tokens whose lifetime exceeds the immutable grant retention")
  void should_reject_token_lifetime_above_maximum_ttl() {
    var token = token(NOW.plusSeconds(900));

    assertThatThrownBy(() -> service.register(token, TENANT, ACTOR, List.of(binding())))
        .isInstanceOf(McpGrantRejectedException.class)
        .hasMessageContaining("maximum");

    verify(verifier, never()).verify(TENANT, ACTOR, List.of(binding()));
    verify(store, never())
        .putIfAbsent(
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any());
  }

  @Test
  @DisplayName("allows only idempotent registration for an already-bound token jti")
  void should_reject_rebinding_same_token_to_different_resources() {
    var token = token(NOW.plusSeconds(120));
    var requested = new McpGrantAuthorization(TENANT, ACTOR, token.expiresAt(), List.of(binding()));
    var existing =
        new McpGrantAuthorization(
            TENANT,
            ACTOR,
            token.expiresAt(),
            List.of(
                new ProviderBindingGrant(
                    "knowledge.graph.query",
                    "knowledge-graph",
                    "query_graph",
                    "2026.07.1",
                    "v1",
                    "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                    "tenant-service-jwt",
                    "CORE",
                    "tenant",
                    "available",
                    NOW,
                    "Query the tenant knowledge graph. Use only for structured relations.")));
    when(store.putIfAbsent("token-jti", requested, Duration.ofSeconds(180))).thenReturn(false);
    when(store.find("token-jti")).thenReturn(Optional.of(existing));

    assertThatThrownBy(() -> service.register(token, TENANT, ACTOR, List.of(binding())))
        .isInstanceOf(McpGrantRejectedException.class)
        .hasMessageContaining("already bound");
  }

  @Test
  @DisplayName("loads only an unexpired record matching every signed token identity field")
  void should_load_only_matching_unexpired_authorization() {
    var token = token(NOW.plusSeconds(120));
    var authorization =
        new McpGrantAuthorization(TENANT, ACTOR, token.expiresAt(), List.of(binding()));
    when(store.find("token-jti")).thenReturn(Optional.of(authorization));

    assertThat(service.findAuthorization(token)).contains(authorization);
    assertThat(
            service.findAuthorization(
                new McpAccessTokenContext(
                    "token-jti", "other-actor", TENANT, "agent-runtime", token.expiresAt())))
        .isEmpty();
  }

  private static McpAccessTokenContext token(Instant expiry) {
    return new McpAccessTokenContext("token-jti", ACTOR, TENANT, "agent-runtime", expiry);
  }

  private static ProviderBindingGrant binding() {
    return new ProviderBindingGrant(
        "knowledge.source.search",
        "ai-methodist",
        "search_methodology_rag",
        "2026.07.1",
        "v1",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "tenant-service-jwt",
        "CORE",
        "tenant",
        "available",
        NOW,
        "Search the tenant methodology knowledge base. Use only for grounded sources.");
  }
}
