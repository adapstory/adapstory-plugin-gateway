package com.adapstory.gateway.config;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URI;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Factory for creating a configured {@link ConfigurableJWTProcessor}.
 *
 * <p>Extracted from {@code PluginAuthFilter} (GRASP HC-1) to isolate JWT processor setup from
 * filter request-handling logic. Single responsibility: assemble the JWT validation pipeline (JWKS
 * source, key selector, claims verifier).
 */
@Component
public class JwtProcessorFactory {

  /**
   * Creates a fully configured JWT processor for plugin token validation.
   *
   * @param jwtConfig JWT configuration (JWKS URI, issuer, audience, cache TTL)
   * @return configured JWT processor
   * @throws java.net.MalformedURLException if JWKS URI is malformed
   */
  public ConfigurableJWTProcessor<SecurityContext> createJwtProcessor(
      GatewayProperties.JwtConfig jwtConfig) throws java.net.MalformedURLException {
    return createJwtProcessor(
        jwtConfig.jwksUri(),
        jwtConfig.issuer(),
        Set.of(jwtConfig.audience()),
        Set.of("sub", "iss", "aud", "exp", "plugin_id", "adapstory_tenant_id", "permissions"),
        jwtConfig.jwksCacheTtlMinutes());
  }

  /**
   * Creates a fully configured JWT processor for plugin token validation from explicit parameters.
   *
   * @param jwksUri JWKS endpoint URI
   * @param issuer token issuer
   * @param audiences accepted audience claims
   * @param requiredClaims required JWT claim names
   * @param jwksCacheTtlMinutes cache TTL for JWKS key material in minutes
   * @return configured JWT processor
   * @throws java.net.MalformedURLException if JWKS URI is malformed
   */
  public ConfigurableJWTProcessor<SecurityContext> createJwtProcessor(
      String jwksUri,
      String issuer,
      Set<String> audiences,
      Set<String> requiredClaims,
      int jwksCacheTtlMinutes)
      throws java.net.MalformedURLException {
    JWKSource<SecurityContext> jwkSource =
        JWKSourceBuilder.create(URI.create(jwksUri).toURL())
            .cache(jwksCacheTtlMinutes * 60L * 1000L, 60_000L)
            .build();

    JWSKeySelector<SecurityContext> keySelector =
        new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

    DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
        new DefaultJWTClaimsVerifier<>(
            audiences, new JWTClaimsSet.Builder().issuer(issuer).build(), requiredClaims, Set.of());

    ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));
    processor.setJWSKeySelector(keySelector);
    processor.setJWTClaimsSetVerifier(claimsVerifier);

    return processor;
  }
}
