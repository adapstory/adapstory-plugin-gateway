package com.adapstory.gateway.mcpgrant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("MCP provider binding grant")
class McpGrantAuthorizationTest {

  private static final Instant EXPIRY = Instant.parse("2026-07-16T12:05:00Z");

  @Test
  @DisplayName("authorizes only the exact registered route and tool")
  void should_authorize_only_exact_binding() {
    var grant =
        new McpGrantAuthorization(
            "00000000-0000-4000-a000-000000000001",
            "actor-1",
            EXPIRY,
            List.of(binding("knowledge.source.search", "ai-methodist", "search_methodology_rag")));

    assertThat(grant.allowsToolList("ai-methodist")).isTrue();
    assertThat(grant.allowsToolCall("ai-methodist", "search_methodology_rag")).isTrue();
    assertThat(grant.allowsToolCall("ai-methodist", "methodology_deep_research")).isFalse();
    assertThat(grant.allowsToolCall("other-provider", "search_methodology_rag")).isFalse();
  }

  @Test
  @DisplayName("rejects duplicate capabilities before a grant can be stored")
  void should_reject_duplicate_capability() {
    assertThatThrownBy(
            () ->
                new McpGrantAuthorization(
                    "00000000-0000-4000-a000-000000000001",
                    "actor-1",
                    EXPIRY,
                    List.of(
                        binding(
                            "knowledge.source.search", "ai-methodist", "search_methodology_rag"),
                        binding("knowledge.source.search", "other-provider", "search"))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("unique");
  }

  @Test
  @DisplayName("rejects legacy or unsafe routing and capability values")
  void should_reject_unsafe_binding_values() {
    assertThatThrownBy(
            () -> binding("knowledge_source_search", "../ai-methodist", "search methodology"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("uses the canonical manifest identifier and ACI description bounds")
  void should_enforce_canonical_manifest_and_description_contract() {
    assertThatThrownBy(() -> binding("knowledge.source.search", "ai-methodist", "UppercaseTool"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new ProviderBindingGrant(
                    "knowledge.source.search",
                    "ai-methodist",
                    "search_sources",
                    "v1",
                    "v1",
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "tenant-service-jwt",
                    "CORE",
                    "tenant",
                    "available",
                    EXPIRY,
                    "too short"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                new ProviderBindingGrant(
                    "knowledge.source.search",
                    "ai-methodist",
                    "search_sources",
                    "v1",
                    "v1",
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "tenant-service-jwt",
                    "CORE",
                    "tenant",
                    "available",
                    EXPIRY,
                    "x".repeat(4097)))
        .isInstanceOf(IllegalArgumentException.class);

    var multiline =
        new ProviderBindingGrant(
            "knowledge.source.search",
            "ai-methodist",
            "search_sources",
            "2026.07.1+reviewed",
            "schema-v1",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "tenant-service-jwt",
            "CORE",
            "tenant",
            "available",
            EXPIRY,
            "Search grounded sources.\nUse only within the active tenant boundary.");
    assertThat(multiline.description()).contains("\n");
  }

  @Test
  @DisplayName("requires between one and thirty-two exact bindings")
  void should_reject_empty_binding_set() {
    assertThatThrownBy(
            () ->
                new McpGrantAuthorization(
                    "00000000-0000-4000-a000-000000000001", "actor-1", EXPIRY, List.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("1..32");
  }

  private static ProviderBindingGrant binding(
      String capability, String routeSlug, String toolName) {
    return new ProviderBindingGrant(
        capability,
        routeSlug,
        toolName,
        "2026.04.1",
        "v1",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "tenant-service-jwt",
        "CORE",
        "tenant",
        "available",
        Instant.parse("2026-07-16T12:00:00Z"),
        "Search the tenant methodology knowledge base. Use for grounded methodology sources only.");
  }
}
