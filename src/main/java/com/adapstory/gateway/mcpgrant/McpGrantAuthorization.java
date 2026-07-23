package com.adapstory.gateway.mcpgrant;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Immutable authorization record shared by every Plugin Gateway replica. */
public record McpGrantAuthorization(
    String tenantId,
    String actorId,
    Instant expiresAt,
    List<ProviderBindingGrant> bindings,
    DelegatedCapabilityAuthority delegatedAuthority) {

  private static final int MAX_BINDINGS = 32;
  private static final int MAX_ACTOR_LENGTH = 512;
  private static final String WORKFLOW_CAPABILITY_PREFIX = "automation.workflow.";

  public McpGrantAuthorization(
      String tenantId, String actorId, Instant expiresAt, List<ProviderBindingGrant> bindings) {
    this(tenantId, actorId, expiresAt, bindings, null);
  }

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
    boolean requiresDelegatedAuthority =
        capabilities.stream().anyMatch(value -> value.startsWith(WORKFLOW_CAPABILITY_PREFIX));
    if (requiresDelegatedAuthority && delegatedAuthority == null) {
      throw new IllegalArgumentException(
          "workflow capability bindings require delegated node authority");
    }
    if (delegatedAuthority != null
        && !new HashSet<>(delegatedAuthority.capabilities()).containsAll(capabilities)) {
      throw new IllegalArgumentException(
          "provider bindings must be a subset of delegated capabilities");
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

  /** Returns the exact route-scoped capability names from this token-bound grant. */
  public List<String> capabilitiesForRoute(String routeSlug) {
    return bindings.stream()
        .filter(binding -> binding.routeSlug().equals(routeSlug))
        .map(ProviderBindingGrant::capability)
        .sorted()
        .toList();
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
