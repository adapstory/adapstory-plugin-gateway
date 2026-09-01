package com.adapstory.gateway.credential;

import com.adapstory.gateway.dto.CredentialBrokerRequest;
import com.adapstory.gateway.dto.CredentialBrokerResponse;

@FunctionalInterface
public interface CredentialBrokerTransport {
  CredentialBrokerResponse forward(CredentialBrokerRequest request);
}
