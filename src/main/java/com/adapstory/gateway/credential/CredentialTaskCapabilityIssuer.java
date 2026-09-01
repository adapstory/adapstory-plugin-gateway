package com.adapstory.gateway.credential;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

public final class CredentialTaskCapabilityIssuer {

  private static final long CAPABILITY_TTL_SECONDS = 60;

  private final CredentialTaskAttestationVerifier verifier;
  private final Clock clock;
  private final Supplier<String> capabilityIdSupplier;

  public CredentialTaskCapabilityIssuer(
      CredentialTaskAttestationVerifier verifier,
      Clock clock,
      Supplier<String> capabilityIdSupplier) {
    this.verifier = Objects.requireNonNull(verifier, "verifier must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.capabilityIdSupplier =
        Objects.requireNonNull(capabilityIdSupplier, "capabilityIdSupplier must not be null");
  }

  /** Verifies the attestation and issues one short-lived route-specific capability. */
  public CredentialTaskCapability issue(
      CredentialAgentHeaders headers, CredentialCapability requiredCapability) {
    CredentialTaskAttestation attestation =
        verifier.verify(
            headers.attestation(),
            headers.attestationSignature(),
            headers.binding(),
            requiredCapability);
    Instant now = clock.instant();
    return new CredentialTaskCapability(
        "CredentialTaskCapability/v1",
        capabilityIdSupplier.get(),
        requiredCapability,
        attestation.beadsTaskId(),
        attestation.agentInstanceId(),
        attestation.policyDigest(),
        now,
        now.plusSeconds(CAPABILITY_TTL_SECONDS));
  }
}
