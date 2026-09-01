package com.adapstory.gateway.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CredentialTaskAttestationVerifierTest {

  private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");

  private KeyPair keyPair;
  private ObjectMapper objectMapper;
  private Set<String> nonces;
  private CredentialTaskAttestationVerifier verifier;

  @BeforeEach
  void setUp() throws Exception {
    keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    objectMapper = new ObjectMapper().findAndRegisterModules();
    nonces = new HashSet<>();
    verifier =
        new CredentialTaskAttestationVerifier(
            objectMapper,
            installationId ->
                "executor-1".equals(installationId)
                    ? Optional.of(keyPair.getPublic())
                    : Optional.empty(),
            (nonce, expiresAt) -> nonces.add(nonce),
            Clock.fixed(NOW, ZoneOffset.UTC));
  }

  @Test
  void verifiesEnrolledExecutorAndEveryCallerBinding() throws Exception {
    CredentialTaskAttestation attestation = attestation(CredentialCapability.PLAN);
    SignedAttestation signed = sign(attestation);

    CredentialTaskAttestation verified =
        verifier.verify(
            signed.payload(),
            signed.signature(),
            CredentialRequestBinding.from(attestation),
            CredentialCapability.PLAN);

    assertThat(verified).isEqualTo(attestation);
  }

  @Test
  void rejectsReplayCrossTaskPolicyAndCapabilityEscalation() throws Exception {
    CredentialTaskAttestation attestation = attestation(CredentialCapability.APPLY);
    SignedAttestation signed = sign(attestation);
    CredentialRequestBinding binding = CredentialRequestBinding.from(attestation);

    verifier.verify(signed.payload(), signed.signature(), binding, CredentialCapability.APPLY);

    assertThatThrownBy(
            () ->
                verifier.verify(
                    signed.payload(), signed.signature(), binding, CredentialCapability.APPLY))
        .isInstanceOf(CredentialCapabilityRejectedException.class)
        .hasMessageContaining("replayed");

    SignedAttestation fresh = sign(attestationWithNonce("nonce-abcdefghijklmnop-2"));
    assertThatThrownBy(
            () ->
                verifier.verify(
                    fresh.payload(),
                    fresh.signature(),
                    new CredentialRequestBinding(
                        "different-task",
                        binding.agentInstanceId(),
                        binding.codexThreadId(),
                        binding.humanMessageDigest(),
                        binding.policyDigest()),
                    CredentialCapability.APPLY))
        .isInstanceOf(CredentialCapabilityRejectedException.class)
        .hasMessageContaining("binding");

    SignedAttestation wrongCapability = sign(attestationWithNonce("nonce-abcdefghijklmnop-3"));
    assertThatThrownBy(
            () ->
                verifier.verify(
                    wrongCapability.payload(),
                    wrongCapability.signature(),
                    binding,
                    CredentialCapability.CONTAIN))
        .isInstanceOf(CredentialCapabilityRejectedException.class)
        .hasMessageContaining("intent");
  }

  @Test
  void rejectsUnknownFieldsUnenrolledKeysAndExpiredAttestations() throws Exception {
    CredentialTaskAttestation attestation = attestation(CredentialCapability.PLAN);
    SignedAttestation signed = sign(attestation);
    com.fasterxml.jackson.databind.node.ObjectNode unknownNode =
        (com.fasterxml.jackson.databind.node.ObjectNode)
            objectMapper.readTree(Base64.getDecoder().decode(signed.payload()));
    unknownNode.put("secret", "must-not-pass");
    byte[] unknownField = unknownNode.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    assertThatThrownBy(
            () ->
                verifier.verify(
                    Base64.getEncoder().encodeToString(unknownField),
                    signBytes(unknownField),
                    CredentialRequestBinding.from(attestation),
                    CredentialCapability.PLAN))
        .isInstanceOf(CredentialCapabilityRejectedException.class);

    CredentialTaskAttestation unknownExecutor =
        new CredentialTaskAttestation(
            attestation.version(),
            "executor-unknown",
            attestation.agentInstanceId(),
            attestation.codexThreadId(),
            attestation.beadsTaskId(),
            attestation.humanMessageDigest(),
            attestation.normalizedIntent(),
            attestation.policyDigest(),
            attestation.issuedAt(),
            "nonce-abcdefghijklmnop-4");
    SignedAttestation unknown = sign(unknownExecutor);
    assertThatThrownBy(
            () ->
                verifier.verify(
                    unknown.payload(),
                    unknown.signature(),
                    CredentialRequestBinding.from(unknownExecutor),
                    CredentialCapability.PLAN))
        .isInstanceOf(CredentialCapabilityRejectedException.class)
        .hasMessageContaining("enrolled");

    CredentialTaskAttestation expired =
        new CredentialTaskAttestation(
            attestation.version(),
            attestation.executorInstallationId(),
            attestation.agentInstanceId(),
            attestation.codexThreadId(),
            attestation.beadsTaskId(),
            attestation.humanMessageDigest(),
            attestation.normalizedIntent(),
            attestation.policyDigest(),
            NOW.minusSeconds(121),
            "nonce-abcdefghijklmnop-5");
    SignedAttestation expiredSigned = sign(expired);
    assertThatThrownBy(
            () ->
                verifier.verify(
                    expiredSigned.payload(),
                    expiredSigned.signature(),
                    CredentialRequestBinding.from(expired),
                    CredentialCapability.PLAN))
        .isInstanceOf(CredentialCapabilityRejectedException.class)
        .hasMessageContaining("expired");
  }

  private CredentialTaskAttestation attestation(CredentialCapability capability) {
    return new CredentialTaskAttestation(
        "CredentialTaskAttestation/v1",
        "executor-1",
        "codex-thread:agent",
        "thread-123",
        "adapstory-ymi3c",
        "a".repeat(64),
        capability.wireValue(),
        "b".repeat(64),
        NOW,
        "nonce-abcdefghijklmnop-1");
  }

  private CredentialTaskAttestation attestationWithNonce(String nonce) {
    CredentialTaskAttestation original = attestation(CredentialCapability.APPLY);
    return new CredentialTaskAttestation(
        original.version(),
        original.executorInstallationId(),
        original.agentInstanceId(),
        original.codexThreadId(),
        original.beadsTaskId(),
        original.humanMessageDigest(),
        original.normalizedIntent(),
        original.policyDigest(),
        original.issuedAt(),
        nonce);
  }

  private SignedAttestation sign(CredentialTaskAttestation attestation) throws Exception {
    byte[] payload = objectMapper.writeValueAsBytes(attestation);
    return new SignedAttestation(Base64.getEncoder().encodeToString(payload), signBytes(payload));
  }

  private String signBytes(byte[] payload) throws Exception {
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(keyPair.getPrivate());
    signer.update(payload);
    return Base64.getEncoder().encodeToString(signer.sign());
  }

  private record SignedAttestation(String payload, String signature) {}
}
