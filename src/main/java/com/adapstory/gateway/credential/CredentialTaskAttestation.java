package com.adapstory.gateway.credential;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record CredentialTaskAttestation(
    String version,
    @JsonProperty("executor_installation_id") String executorInstallationId,
    @JsonProperty("agent_instance_id") String agentInstanceId,
    @JsonProperty("codex_thread_id") String codexThreadId,
    @JsonProperty("beads_task_id") String beadsTaskId,
    @JsonProperty("human_message_digest") String humanMessageDigest,
    @JsonProperty("normalized_intent") String normalizedIntent,
    @JsonProperty("policy_digest") String policyDigest,
    @JsonProperty("issued_at") Instant issuedAt,
    String nonce) {
  public CredentialTaskAttestation {
    if (!"CredentialTaskAttestation/v1".equals(version)
        || isBlank(executorInstallationId)
        || isBlank(agentInstanceId)
        || isBlank(codexThreadId)
        || isBlank(beadsTaskId)
        || isBlank(humanMessageDigest)
        || isBlank(normalizedIntent)
        || isBlank(policyDigest)
        || issuedAt == null
        || isBlank(nonce)) {
      throw new CredentialCapabilityRejectedException("incomplete credential task attestation");
    }
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }
}
