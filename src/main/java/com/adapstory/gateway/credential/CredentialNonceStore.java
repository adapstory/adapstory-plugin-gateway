package com.adapstory.gateway.credential;

import java.time.Instant;

@FunctionalInterface
public interface CredentialNonceStore {
  boolean consume(String nonce, Instant expiresAt);
}
