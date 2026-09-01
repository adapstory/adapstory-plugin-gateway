package com.adapstory.gateway.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class CredentialGatewayAssertionSignerTest {

  @Test
  void signsBrokerCompatibleCanonicalMethodBodyAndCallerBinding() throws Exception {
    Instant now = Instant.parse("2026-09-01T12:00:00Z");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
    CredentialGatewayAssertionSigner signer =
        new CredentialGatewayAssertionSigner(
            objectMapper,
            keyPair.getPrivate(),
            "credential-broker",
            Clock.fixed(now, ZoneOffset.UTC),
            () -> "nonce-abcdefghijklmnop");
    CredentialTaskCapability capability =
        new CredentialTaskCapability(
            "CredentialTaskCapability/v1",
            "capability-1",
            CredentialCapability.PLAN,
            "adapstory-ymi3c",
            "codex-thread:agent",
            "b".repeat(64),
            now,
            now.plusSeconds(60));
    JsonNode body = objectMapper.readTree("{\"z\":1,\"a\":{\"y\":2,\"x\":3}}");

    SignedGatewayAssertion signed = signer.sign("POST /v1/plans", body, "request-1", capability);

    byte[] payload = Base64.getDecoder().decode(signed.assertion());
    Signature verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(keyPair.getPublic());
    verifier.update(payload);
    assertThat(verifier.verify(Base64.getDecoder().decode(signed.signature()))).isTrue();
    JsonNode assertion = objectMapper.readTree(payload);
    assertThat(assertion.path("version").asText()).isEqualTo("CredentialGatewayAssertion/v1");
    assertThat(assertion.path("method").asText()).isEqualTo("POST /v1/plans");
    assertThat(assertion.path("body_digest").asText())
        .isEqualTo(CanonicalCredentialJson.sha256(body));
    assertThat(assertion.path("audience").asText()).isEqualTo("credential-broker");
    assertThat(assertion.path("capability").asText()).isEqualTo("credential.lifecycle.plan");
    assertThat(assertion.path("task_id").asText()).isEqualTo("adapstory-ymi3c");
    assertThat(assertion.path("agent_instance_id").asText()).isEqualTo("codex-thread:agent");
    assertThat(assertion.path("expires_at").asLong() - assertion.path("issued_at").asLong())
        .isEqualTo(60);
  }
}
