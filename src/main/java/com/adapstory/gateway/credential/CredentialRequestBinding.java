package com.adapstory.gateway.credential;

public record CredentialRequestBinding(
    String beadsTaskId,
    String agentInstanceId,
    String codexThreadId,
    String humanMessageDigest,
    String policyDigest) {

  public CredentialRequestBinding {
    if (isBlank(beadsTaskId)
        || isBlank(agentInstanceId)
        || isBlank(codexThreadId)
        || isBlank(humanMessageDigest)
        || isBlank(policyDigest)) {
      throw new CredentialCapabilityRejectedException("incomplete credential request binding");
    }
  }

  /** Creates the expected caller binding from an already parsed attestation. */
  public static CredentialRequestBinding from(CredentialTaskAttestation attestation) {
    return new CredentialRequestBinding(
        attestation.beadsTaskId(),
        attestation.agentInstanceId(),
        attestation.codexThreadId(),
        attestation.humanMessageDigest(),
        attestation.policyDigest());
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }
}
