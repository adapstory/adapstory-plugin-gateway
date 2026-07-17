package com.adapstory.gateway.mcpgrant;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Immutable authorization record shared by every Plugin Gateway replica. */
public record McpGrantAuthorization(
    String tenantId, String actorId, Instant expiresAt, List<ProviderBindingGrant> bindings) {

  private static final int MAX_BINDINGS = 32;
  private static final int MAX_ACTOR_LENGTH = 512;

  public McpGrantAuthorization {
    tenantId = requireContextValue(tenantId, "tenantId");
    actorId = requireActorId(actorId);
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    if (bindings == null || bindings.isEmpty() || bindings.size() > MAX_BINDINGS) {
      throw new IllegalArgumentException("bindings must contain 1..32 entries");
    }
    bindings = List.copyOf(bindings);
    Set<String> capabilities = new HashSet<>();
    Set<String> providerTools = new HashSet<>();
    for (ProviderBindingGrant binding : bindings) {
      Objects.requireNonNull(binding, "bindings must not contain null entries");
      if (!capabilities.add(binding.capability())) {
        throw new IllegalArgumentException("binding capabilities must be unique");
      }
      if (!providerTools.add(binding.routeSlug() + "\u0000" + binding.toolName())) {
        throw new IllegalArgumentException("provider tool bindings must be unique");
      }
    }
  }

  /** Returns whether this grant permits schema discovery for the exact provider route. */
  public boolean allowsToolList(String routeSlug) {
    return bindings.stream().anyMatch(binding -> binding.routeSlug().equals(routeSlug));
  }

  /** Returns whether this grant permits invoking the exact provider route and MCP tool name. */
  public boolean allowsToolCall(String routeSlug, String toolName) {
    return bindings.stream()
        .anyMatch(
            binding ->
                binding.routeSlug().equals(routeSlug) && binding.toolName().equals(toolName));
  }

  private static String requireActorId(String value) {
    return requireContextValue(value, "actorId");
  }

  private static String requireContextValue(String value, String field) {
    if (value == null
        || value.isBlank()
        || value.length() > MAX_ACTOR_LENGTH
        || value
            .chars()
            .anyMatch(
                character ->
                    Character.isWhitespace(character) || Character.isISOControl(character))) {
      throw new IllegalArgumentException(field + " is not canonical");
    }
    return value;
  }
}
