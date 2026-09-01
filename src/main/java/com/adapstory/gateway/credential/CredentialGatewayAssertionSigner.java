package com.adapstory.gateway.credential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Supplier;

public final class CredentialGatewayAssertionSigner {

  private static final long ASSERTION_TTL_SECONDS = 60;

  private final ObjectMapper objectMapper;
  private final PrivateKey privateKey;
  private final String audience;
  private final Clock clock;
  private final Supplier<String> nonceSupplier;

  public CredentialGatewayAssertionSigner(
      ObjectMapper objectMapper,
      PrivateKey privateKey,
      String audience,
      Clock clock,
      Supplier<String> nonceSupplier) {
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    if (audience == null || audience.isBlank()) {
      throw new IllegalArgumentException("Broker audience is required");
    }
    this.audience = audience;
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.nonceSupplier = Objects.requireNonNull(nonceSupplier, "nonceSupplier must not be null");
  }

  /** Signs the exact Broker method, canonical body digest, request, and caller capability. */
  public SignedGatewayAssertion sign(
      String method, JsonNode body, String requestId, CredentialTaskCapability capability) {
    Instant now = clock.instant();
    capability.requireCaller(
        capability.beadsTaskId(), capability.agentInstanceId(), capability.capability(), now);
    CredentialGatewayAssertion assertion =
        new CredentialGatewayAssertion(
            "CredentialGatewayAssertion/v1",
            method,
            CanonicalCredentialJson.sha256(body),
            requestId,
            audience,
            capability.capability().wireValue(),
            capability.capabilityId(),
            capability.beadsTaskId(),
            capability.agentInstanceId(),
            now.getEpochSecond(),
            now.plusSeconds(ASSERTION_TTL_SECONDS).getEpochSecond(),
            nonceSupplier.get());
    try {
      byte[] payload = objectMapper.writeValueAsBytes(assertion);
      Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(privateKey);
      signer.update(payload);
      return new SignedGatewayAssertion(
          Base64.getEncoder().encodeToString(payload),
          Base64.getEncoder().encodeToString(signer.sign()));
    } catch (GeneralSecurityException | java.io.IOException exception) {
      throw new IllegalStateException("Gateway assertion signing failed", exception);
    }
  }
}
