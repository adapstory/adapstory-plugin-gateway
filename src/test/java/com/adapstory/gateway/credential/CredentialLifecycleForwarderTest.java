package com.adapstory.gateway.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.adapstory.gateway.dto.CredentialBrokerRequest;
import com.adapstory.gateway.dto.CredentialBrokerResponse;
import com.fasterxml.jackson.databind.JsonNode;
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
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class CredentialLifecycleForwarderTest {

  @Test
  void mintsRouteDerivedCapabilityAndForwardsOnlySignedBrokerHeaders() throws Exception {
    Instant now = Instant.parse("2026-09-01T12:00:00Z");
    Clock clock = Clock.fixed(now, ZoneOffset.UTC);
    ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
    KeyPair executor = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair gateway = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Set<String> nonces = new HashSet<>();
    CredentialTaskAttestationVerifier verifier =
        new CredentialTaskAttestationVerifier(
            objectMapper,
            ignored -> Optional.of(executor.getPublic()),
            (nonce, expiresAt) -> nonces.add(nonce),
            clock);
    CredentialTaskCapabilityIssuer issuer =
        new CredentialTaskCapabilityIssuer(verifier, clock, () -> "capability-1");
    CredentialGatewayAssertionSigner assertionSigner =
        new CredentialGatewayAssertionSigner(
            objectMapper,
            gateway.getPrivate(),
            "credential-broker",
            clock,
            () -> "gateway-nonce-abcdefgh");
    AtomicReference<CredentialBrokerRequest> captured = new AtomicReference<>();
    CredentialBrokerTransport transport =
        request -> {
          captured.set(request);
          return new CredentialBrokerResponse(201, objectMapper.createObjectNode().put("ok", true));
        };
    CredentialLifecycleForwarder forwarder =
        new CredentialLifecycleForwarder(issuer, assertionSigner, transport);
    CredentialTaskAttestation attestation = attestation(now, CredentialCapability.PLAN);
    byte[] attestationJson = objectMapper.writeValueAsBytes(attestation);
    CredentialAgentHeaders headers =
        new CredentialAgentHeaders(
            Base64.getEncoder().encodeToString(attestationJson),
            sign(executor, attestationJson),
            attestation.beadsTaskId(),
            attestation.agentInstanceId(),
            attestation.codexThreadId(),
            attestation.humanMessageDigest(),
            attestation.policyDigest(),
            "request-1");
    JsonNode body = objectMapper.readTree("{\"operation\":\"rotate\"}");

    CredentialBrokerResponse response =
        forwarder.forward(CredentialCapability.PLAN, "POST /v1/plans", "/v1/plans", body, headers);

    assertThat(response.status()).isEqualTo(201);
    assertThat(captured.get().path()).isEqualTo("/v1/plans");
    assertThat(captured.get().assertion()).isNotBlank();
    assertThat(captured.get().signature()).isNotBlank();
    JsonNode forwardedAssertion =
        objectMapper.readTree(Base64.getDecoder().decode(captured.get().assertion()));
    assertThat(forwardedAssertion.path("capability").asText())
        .isEqualTo("credential.lifecycle.plan");
    assertThat(forwardedAssertion.path("body_digest").asText())
        .isEqualTo(CanonicalCredentialJson.sha256(body));
  }

  @Test
  void containmentAttestationCannotAuthorizeGenericApplyRoute() throws Exception {
    Instant now = Instant.parse("2026-09-01T12:00:00Z");
    ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
    KeyPair executor = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair gateway = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    CredentialTaskAttestationVerifier verifier =
        new CredentialTaskAttestationVerifier(
            objectMapper,
            ignored -> Optional.of(executor.getPublic()),
            (nonce, expiresAt) -> true,
            Clock.fixed(now, ZoneOffset.UTC));
    CredentialLifecycleForwarder forwarder =
        new CredentialLifecycleForwarder(
            new CredentialTaskCapabilityIssuer(
                verifier, Clock.fixed(now, ZoneOffset.UTC), () -> "cap"),
            new CredentialGatewayAssertionSigner(
                objectMapper,
                gateway.getPrivate(),
                "credential-broker",
                Clock.fixed(now, ZoneOffset.UTC),
                () -> "gateway-nonce-abcdefgh"),
            request -> new CredentialBrokerResponse(202, objectMapper.createObjectNode()));
    CredentialTaskAttestation attestation = attestation(now, CredentialCapability.CONTAIN);
    byte[] payload = objectMapper.writeValueAsBytes(attestation);
    CredentialAgentHeaders headers =
        new CredentialAgentHeaders(
            Base64.getEncoder().encodeToString(payload),
            sign(executor, payload),
            attestation.beadsTaskId(),
            attestation.agentInstanceId(),
            attestation.codexThreadId(),
            attestation.humanMessageDigest(),
            attestation.policyDigest(),
            "request-2");

    assertThatThrownBy(
            () ->
                forwarder.forward(
                    CredentialCapability.APPLY,
                    "POST /v1/operations",
                    "/v1/operations",
                    objectMapper.createObjectNode(),
                    headers))
        .isInstanceOf(CredentialCapabilityRejectedException.class)
        .hasMessageContaining("intent");
  }

  private static CredentialTaskAttestation attestation(
      Instant now, CredentialCapability capability) {
    return new CredentialTaskAttestation(
        "CredentialTaskAttestation/v1",
        "executor-1",
        "codex-thread:agent",
        "thread-123",
        "adapstory-ymi3c",
        "a".repeat(64),
        capability.wireValue(),
        "b".repeat(64),
        now,
        "executor-nonce-abcdefgh");
  }

  private static String sign(KeyPair keyPair, byte[] payload) throws Exception {
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(keyPair.getPrivate());
    signer.update(payload);
    return Base64.getEncoder().encodeToString(signer.sign());
  }
}
