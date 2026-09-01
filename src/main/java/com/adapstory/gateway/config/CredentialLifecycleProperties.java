package com.adapstory.gateway.config;

import java.net.URI;
import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("gateway.credential-lifecycle")
public record CredentialLifecycleProperties(
    boolean enabled,
    URI brokerBaseUri,
    String brokerAudience,
    Path signingPrivateKeyFile,
    Path executorPublicKeyDirectory,
    String nonceRedisPrefix) {

  public CredentialLifecycleProperties {
    if (enabled
        && (brokerBaseUri == null
            || brokerAudience == null
            || brokerAudience.isBlank()
            || signingPrivateKeyFile == null
            || executorPublicKeyDirectory == null
            || nonceRedisPrefix == null
            || nonceRedisPrefix.isBlank())) {
      throw new IllegalArgumentException(
          "enabled credential lifecycle Gateway requires complete runtime authority configuration");
    }
  }
}
