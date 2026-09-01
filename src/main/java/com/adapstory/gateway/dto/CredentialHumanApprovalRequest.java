package com.adapstory.gateway.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialHumanApprovalRequest(
    @JsonProperty("plan_digest") String planDigest,
    String nonce,
    @JsonProperty("expires_at") long expiresAt) {

  public CredentialHumanApprovalRequest {
    if (planDigest == null
        || !planDigest.matches("^[a-f0-9]{64}$")
        || nonce == null
        || nonce.length() < 16) {
      throw new IllegalArgumentException("invalid human approval request");
    }
  }
}
