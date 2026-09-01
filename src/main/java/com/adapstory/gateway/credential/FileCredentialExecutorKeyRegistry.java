package com.adapstory.gateway.credential;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

public final class FileCredentialExecutorKeyRegistry implements CredentialExecutorKeyRegistry {

  private final Path directory;

  public FileCredentialExecutorKeyRegistry(Path directory) {
    this.directory = directory.toAbsolutePath().normalize();
  }

  @Override
  public Optional<PublicKey> findEnrolledKey(String executorInstallationId) {
    if (executorInstallationId == null
        || !executorInstallationId.matches("^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$")) {
      return Optional.empty();
    }
    Path candidate = directory.resolve(executorInstallationId + ".pem").normalize();
    if (!directory.equals(candidate.getParent()) || !Files.isRegularFile(candidate)) {
      return Optional.empty();
    }
    try {
      String encoded =
          Files.readString(candidate)
              .replace("-----BEGIN PUBLIC KEY-----", "")
              .replace("-----END PUBLIC KEY-----", "")
              .replaceAll("\\s", "");
      return Optional.of(
          KeyFactory.getInstance("Ed25519")
              .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encoded))));
    } catch (IOException | GeneralSecurityException | IllegalArgumentException exception) {
      return Optional.empty();
    }
  }
}
