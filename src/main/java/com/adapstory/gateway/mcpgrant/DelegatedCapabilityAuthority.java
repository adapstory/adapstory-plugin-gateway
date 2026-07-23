package com.adapstory.gateway.mcpgrant;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Immutable PDLC node authority stored with one exchanged-token grant. */
public record DelegatedCapabilityAuthority(
    UUID runId, String nodeId, UUID grantId, String policyVersion, List<String> capabilities) {

  private static final Pattern NODE_ID = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$");
  private static final Pattern POLICY_VERSION =
      Pattern.compile(
          "^[a-z0-9]+(?:-[a-z0-9]+)*@"
              + "(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$");
  private static final Pattern CAPABILITY =
      Pattern.compile("^[a-z][a-z0-9]*(?:-[a-z0-9]+)*" + "(?:\\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$");

  public DelegatedCapabilityAuthority {
    if (runId == null || grantId == null) {
      throw new IllegalArgumentException("delegated authority IDs are required");
    }
    if (nodeId == null || !NODE_ID.matcher(nodeId).matches()) {
      throw new IllegalArgumentException("delegated authority nodeId is not canonical");
    }
    if (policyVersion == null || !POLICY_VERSION.matcher(policyVersion).matches()) {
      throw new IllegalArgumentException("delegated authority policyVersion is not canonical");
    }
    if (capabilities == null || capabilities.isEmpty() || capabilities.size() > 32) {
      throw new IllegalArgumentException(
          "delegated authority capabilities must contain 1..32 entries");
    }
    capabilities = List.copyOf(capabilities);
    Set<String> unique = new HashSet<>();
    String previous = null;
    for (String capability : capabilities) {
      if (capability == null
          || !CAPABILITY.matcher(capability).matches()
          || !unique.add(capability)
          || (previous != null && previous.compareTo(capability) >= 0)) {
        throw new IllegalArgumentException(
            "delegated authority capabilities must be canonical, unique, and sorted");
      }
      previous = capability;
    }
  }
}
