package com.adapstory.gateway.credential;

import java.security.PublicKey;
import java.util.Optional;

@FunctionalInterface
public interface CredentialExecutorKeyRegistry {
  Optional<PublicKey> findEnrolledKey(String executorInstallationId);
}
