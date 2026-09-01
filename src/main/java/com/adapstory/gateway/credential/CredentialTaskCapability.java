package com.adapstory.gateway.credential;

import java.time.Instant;

public record CredentialTaskCapability(
    String version,
    String capabilityId,
    CredentialCapability capability,
    String beadsTaskId,
    String agentInstanceId,
    String policyDigest,
    Instant issuedAt,
    Instant expiresAt) {
  public CredentialTaskCapability {
    if (!"CredentialTaskCapability/v1".equals(version)
        || capabilityId == null
        || capabilityId.isBlank()
        || capability == null
        || beadsTaskId == null
        || beadsTaskId.isBlank()
        || agentInstanceId == null
        || agentInstanceId.isBlank()
        || policyDigest == null
        || policyDigest.isBlank()
        || issuedAt == null
        || expiresAt == null
        || expiresAt.isAfter(issuedAt.plusSeconds(120))
        || !expiresAt.isAfter(issuedAt)) {
      throw new CredentialCapabilityRejectedException("invalid credential task capability");
    }
  }

  /** Rejects use outside the exact task, Agent Instance, capability, or validity window. */
  public void requireCaller(
      String taskId, String agentId, CredentialCapability required, Instant now) {
    if (!beadsTaskId.equals(taskId)
        || !agentInstanceId.equals(agentId)
        || capability != required
        || now.isBefore(issuedAt.minusSeconds(5))
        || !now.isBefore(expiresAt)) {
      throw new CredentialCapabilityRejectedException(
          "credential task capability binding mismatch");
    }
  }
}
