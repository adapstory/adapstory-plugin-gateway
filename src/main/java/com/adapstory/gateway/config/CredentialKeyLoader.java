package com.adapstory.gateway.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

final class CredentialKeyLoader {

  private CredentialKeyLoader() {}

  static PrivateKey loadPrivateKey(Path path) {
    byte[] encoded = null;
    try {
      encoded = Files.readAllBytes(path);
      return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    } catch (IOException | GeneralSecurityException exception) {
      throw new IllegalStateException("Credential Gateway signing key is unavailable", exception);
    } finally {
      if (encoded != null) {
        Arrays.fill(encoded, (byte) 0);
      }
    }
  }
}
