package com.adapstory.gateway.config;

import com.adapstory.gateway.credential.CredentialBrokerTransport;
import com.adapstory.gateway.credential.CredentialExecutorKeyRegistry;
import com.adapstory.gateway.credential.CredentialGatewayAssertionSigner;
import com.adapstory.gateway.credential.CredentialHumanApprovalForwarder;
import com.adapstory.gateway.credential.CredentialLifecycleForwarder;
import com.adapstory.gateway.credential.CredentialNonceStore;
import com.adapstory.gateway.credential.CredentialTaskAttestationVerifier;
import com.adapstory.gateway.credential.CredentialTaskCapabilityIssuer;
import com.adapstory.gateway.credential.FileCredentialExecutorKeyRegistry;
import com.adapstory.gateway.credential.RedisCredentialNonceStore;
import com.adapstory.gateway.credential.RestClientCredentialBrokerTransport;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.client.RestClient;

@Configuration
@EnableConfigurationProperties(CredentialLifecycleProperties.class)
@ConditionalOnProperty(name = "gateway.credential-lifecycle.enabled", havingValue = "true")
public class CredentialLifecycleConfiguration {

  @Bean
  CredentialNonceStore credentialNonceStore(
      StringRedisTemplate redis, CredentialLifecycleProperties properties) {
    return new RedisCredentialNonceStore(redis, Clock.systemUTC(), properties.nonceRedisPrefix());
  }

  @Bean
  CredentialExecutorKeyRegistry credentialExecutorKeyRegistry(
      CredentialLifecycleProperties properties) {
    return new FileCredentialExecutorKeyRegistry(properties.executorPublicKeyDirectory());
  }

  @Bean
  CredentialTaskAttestationVerifier credentialTaskAttestationVerifier(
      ObjectMapper objectMapper,
      CredentialExecutorKeyRegistry keyRegistry,
      CredentialNonceStore nonceStore) {
    return new CredentialTaskAttestationVerifier(
        objectMapper, keyRegistry, nonceStore, Clock.systemUTC());
  }

  @Bean
  CredentialTaskCapabilityIssuer credentialTaskCapabilityIssuer(
      CredentialTaskAttestationVerifier verifier) {
    return new CredentialTaskCapabilityIssuer(
        verifier, Clock.systemUTC(), () -> "cap_" + UUID.randomUUID().toString().replace("-", ""));
  }

  @Bean
  CredentialGatewayAssertionSigner credentialGatewayAssertionSigner(
      ObjectMapper objectMapper, CredentialLifecycleProperties properties) {
    return new CredentialGatewayAssertionSigner(
        objectMapper,
        CredentialKeyLoader.loadPrivateKey(properties.signingPrivateKeyFile()),
        properties.brokerAudience(),
        Clock.systemUTC(),
        () -> UUID.randomUUID().toString().replace("-", ""));
  }

  @Bean
  CredentialBrokerTransport credentialBrokerTransport(
      RestClient.Builder restClientBuilder,
      ObjectMapper objectMapper,
      CredentialLifecycleProperties properties) {
    return new RestClientCredentialBrokerTransport(
        restClientBuilder.baseUrl(properties.brokerBaseUri().toString()).build(), objectMapper);
  }

  @Bean
  CredentialLifecycleForwarder credentialLifecycleForwarder(
      CredentialTaskCapabilityIssuer issuer,
      CredentialGatewayAssertionSigner signer,
      CredentialBrokerTransport transport) {
    return new CredentialLifecycleForwarder(issuer, signer, transport);
  }

  @Bean
  CredentialHumanApprovalForwarder credentialHumanApprovalForwarder(
      CredentialGatewayAssertionSigner signer, CredentialBrokerTransport transport) {
    return new CredentialHumanApprovalForwarder(
        signer,
        transport,
        Clock.systemUTC(),
        () -> "human_approval_" + UUID.randomUUID().toString().replace("-", ""));
  }
}
