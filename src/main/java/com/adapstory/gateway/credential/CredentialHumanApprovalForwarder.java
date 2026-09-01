package com.adapstory.gateway.credential;

import com.adapstory.gateway.dto.CredentialBrokerRequest;
import com.adapstory.gateway.dto.CredentialBrokerResponse;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

public final class CredentialHumanApprovalForwarder {

  private final CredentialGatewayAssertionSigner signer;
  private final CredentialBrokerTransport transport;
  private final Clock clock;
  private final Supplier<String> capabilityIdSupplier;

  public CredentialHumanApprovalForwarder(
      CredentialGatewayAssertionSigner signer,
      CredentialBrokerTransport transport,
      Clock clock,
      Supplier<String> capabilityIdSupplier) {
    this.signer = Objects.requireNonNull(signer, "signer must not be null");
    this.transport = Objects.requireNonNull(transport, "transport must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.capabilityIdSupplier = capabilityIdSupplier;
  }

  /** Forwards one OIDC-derived approval without accepting identity fields from request JSON. */
  public CredentialBrokerResponse forward(
      String planRef, JsonNode body, String requestId, CredentialHumanApprovalIdentity identity) {
    Instant now = clock.instant();
    CredentialTaskCapability internalCapability =
        new CredentialTaskCapability(
            "CredentialTaskCapability/v1",
            capabilityIdSupplier.get(),
            CredentialCapability.APPLY,
            "human-approval:" + planRef,
            "human:" + identity.subject(),
            body.path("plan_digest").asText(),
            now,
            now.plusSeconds(60));
    SignedGatewayAssertion assertion =
        signer.sign("POST /v1/plans/{plan_ref}/approvals", body, requestId, internalCapability);
    return transport.forward(
        new CredentialBrokerRequest(
            "POST",
            "/v1/plans/" + planRef + "/approvals",
            body,
            assertion.assertion(),
            assertion.signature(),
            requestId));
  }
}
