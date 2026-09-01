package com.adapstory.gateway.credential;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

public final class CredentialTaskAttestationVerifier {

  static final long MAX_ATTESTATION_AGE_SECONDS = 120;
  private static final long CLOCK_SKEW_SECONDS = 5;

  private final ObjectMapper objectMapper;
  private final CredentialExecutorKeyRegistry keyRegistry;
  private final CredentialNonceStore nonceStore;
  private final Clock clock;

  public CredentialTaskAttestationVerifier(
      ObjectMapper objectMapper,
      CredentialExecutorKeyRegistry keyRegistry,
      CredentialNonceStore nonceStore,
      Clock clock) {
    this.objectMapper =
        Objects.requireNonNull(objectMapper, "objectMapper must not be null")
            .copy()
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    this.keyRegistry = Objects.requireNonNull(keyRegistry, "keyRegistry must not be null");
    this.nonceStore = Objects.requireNonNull(nonceStore, "nonceStore must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** Verifies an enrolled executor signature and consumes the single-use attestation nonce. */
  public CredentialTaskAttestation verify(
      String assertionBase64,
      String signatureBase64,
      CredentialRequestBinding expected,
      CredentialCapability requiredCapability) {
    byte[] assertion = decode(assertionBase64, "attestation");
    CredentialTaskAttestation attestation = parse(assertion);
    PublicKey key =
        keyRegistry
            .findEnrolledKey(attestation.executorInstallationId())
            .orElseThrow(
                () ->
                    new CredentialCapabilityRejectedException(
                        "executor installation is not enrolled"));
    verifySignature(key, assertion, decode(signatureBase64, "signature"));
    verifyFreshness(attestation);
    verifyBinding(attestation, expected, requiredCapability);
    Instant expiresAt = attestation.issuedAt().plusSeconds(MAX_ATTESTATION_AGE_SECONDS);
    if (!nonceStore.consume(attestation.nonce(), expiresAt)) {
      throw new CredentialCapabilityRejectedException("credential task attestation replayed");
    }
    return attestation;
  }

  private CredentialTaskAttestation parse(byte[] assertion) {
    try {
      return objectMapper.readValue(assertion, CredentialTaskAttestation.class);
    } catch (IOException exception) {
      throw new CredentialCapabilityRejectedException("invalid credential task attestation");
    }
  }

  private void verifyFreshness(CredentialTaskAttestation attestation) {
    Instant now = clock.instant();
    if (attestation.issuedAt().isAfter(now.plusSeconds(CLOCK_SKEW_SECONDS))
        || !now.isBefore(attestation.issuedAt().plusSeconds(MAX_ATTESTATION_AGE_SECONDS))) {
      throw new CredentialCapabilityRejectedException("credential task attestation expired");
    }
  }

  private static void verifyBinding(
      CredentialTaskAttestation attestation,
      CredentialRequestBinding expected,
      CredentialCapability requiredCapability) {
    if (!attestation.beadsTaskId().equals(expected.beadsTaskId())
        || !attestation.agentInstanceId().equals(expected.agentInstanceId())
        || !attestation.codexThreadId().equals(expected.codexThreadId())
        || !attestation.humanMessageDigest().equals(expected.humanMessageDigest())
        || !attestation.policyDigest().equals(expected.policyDigest())) {
      throw new CredentialCapabilityRejectedException(
          "credential task attestation binding mismatch");
    }
    if (!attestation.normalizedIntent().equals(requiredCapability.wireValue())) {
      throw new CredentialCapabilityRejectedException(
          "credential task attestation intent mismatch");
    }
  }

  private static void verifySignature(PublicKey key, byte[] payload, byte[] signatureBytes) {
    try {
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(key);
      verifier.update(payload);
      if (!verifier.verify(signatureBytes)) {
        throw new CredentialCapabilityRejectedException(
            "credential task attestation signature invalid");
      }
    } catch (GeneralSecurityException exception) {
      throw new CredentialCapabilityRejectedException(
          "credential task attestation signature invalid");
    }
  }

  private static byte[] decode(String value, String label) {
    if (value == null || value.isBlank()) {
      throw new CredentialCapabilityRejectedException(label + " is required");
    }
    try {
      return Base64.getDecoder().decode(value.getBytes(StandardCharsets.US_ASCII));
    } catch (IllegalArgumentException exception) {
      throw new CredentialCapabilityRejectedException(label + " is not canonical base64");
    }
  }
}
