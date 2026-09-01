package com.adapstory.gateway.credential;

import java.time.Instant;

public record CredentialTaskAttestation(
    String version,
    String executorInstallationId,
    String agentInstanceId,
    String codexThreadId,
    String beadsTaskId,
    String humanMessageDigest,
    String normalizedIntent,
    String policyDigest,
    Instant issuedAt,
    String nonce
) {
    public CredentialTaskAttestation {
        if (!"CredentialTaskAttestation/v1".equals(version)
            || isBlank(executorInstallationId)
            || isBlank(agentInstanceId)
            || isBlank(codexThreadId)
            || isBlank(beadsTaskId)
            || isBlank(humanMessageDigest)
            || isBlank(normalizedIntent)
            || isBlank(policyDigest)
            || isBlank(nonce)) {
            throw new CredentialCapabilityRejectedException("incomplete credential task attestation");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
