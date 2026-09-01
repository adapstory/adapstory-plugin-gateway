package com.adapstory.gateway.credential;

public record CredentialAgentHeaders(
    String attestation,
    String attestationSignature,
    String beadsTaskId,
    String agentInstanceId,
    String codexThreadId,
    String humanMessageDigest,
    String policyDigest,
    String requestId) {

  public CredentialAgentHeaders {
    if (attestation == null
        || attestation.isBlank()
        || attestationSignature == null
        || attestationSignature.isBlank()
        || requestId == null
        || !requestId.matches("^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}$")) {
      throw new CredentialCapabilityRejectedException("incomplete credential request headers");
    }
  }

  public CredentialRequestBinding binding() {
    return new CredentialRequestBinding(
        beadsTaskId, agentInstanceId, codexThreadId, humanMessageDigest, policyDigest);
  }
}
