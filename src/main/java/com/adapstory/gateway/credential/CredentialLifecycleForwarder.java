package com.adapstory.gateway.credential;

import com.adapstory.gateway.dto.CredentialBrokerRequest;
import com.adapstory.gateway.dto.CredentialBrokerResponse;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Objects;

public final class CredentialLifecycleForwarder {

  private final CredentialTaskCapabilityIssuer issuer;
  private final CredentialGatewayAssertionSigner signer;
  private final CredentialBrokerTransport transport;

  public CredentialLifecycleForwarder(
      CredentialTaskCapabilityIssuer issuer,
      CredentialGatewayAssertionSigner signer,
      CredentialBrokerTransport transport) {
    this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
    this.signer = Objects.requireNonNull(signer, "signer must not be null");
    this.transport = Objects.requireNonNull(transport, "transport must not be null");
  }

  /** Mints the route-derived task capability and forwards one signed Broker request. */
  public CredentialBrokerResponse forward(
      CredentialCapability requiredCapability,
      String brokerMethod,
      String brokerPath,
      JsonNode body,
      CredentialAgentHeaders headers) {
    CredentialTaskCapability capability = issuer.issue(headers, requiredCapability);
    SignedGatewayAssertion assertion =
        signer.sign(brokerMethod, body, headers.requestId(), capability);
    String httpMethod = brokerMethod.substring(0, brokerMethod.indexOf(' '));
    return transport.forward(
        new CredentialBrokerRequest(
            httpMethod,
            brokerPath,
            body,
            assertion.assertion(),
            assertion.signature(),
            headers.requestId()));
  }
}
