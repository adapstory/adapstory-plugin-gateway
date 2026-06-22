package com.adapstory.gateway.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("JwtProcessorFactory")
class JwtProcessorFactoryTest {

  @Test
  @DisplayName("should accept Keycloak access tokens with additional audiences")
  void should_acceptKeycloakAccessToken_when_expectedAudienceIsOneOfMany() throws Exception {
    GatewayProperties.JwtConfig config =
        new GatewayProperties.JwtConfig(
            "http://localhost:8180/realms/adapstory/protocol/openid-connect/certs",
            "https://auth.dev.adapstory.com/realms/adapstory",
            "adapstory-plugin-gateway",
            5);
    ConfigurableJWTProcessor<SecurityContext> processor =
        new JwtProcessorFactory().createJwtProcessor(config);
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("adapstory-bc10-service")
            .issuer("https://auth.dev.adapstory.com/realms/adapstory")
            .audience(List.of("account", "adapstory-plugin-gateway", "adapstory-bc10-service"))
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .claim("plugin_id", "adapstory.ai.course-generator")
            .claim("adapstory_tenant_id", "00000000-0000-4000-a000-000000000001")
            .claim("permissions", List.of("dify-plugin:mcp", "edu-knowledge-graph:mcp"))
            .build();

    assertThatCode(() -> processor.getJWTClaimsSetVerifier().verify(claims, null))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("should reject tokens without the configured plugin gateway audience")
  void should_rejectToken_when_expectedAudienceIsMissing() throws Exception {
    GatewayProperties.JwtConfig config =
        new GatewayProperties.JwtConfig(
            "http://localhost:8180/realms/adapstory/protocol/openid-connect/certs",
            "https://auth.dev.adapstory.com/realms/adapstory",
            "adapstory-plugin-gateway",
            5);
    ConfigurableJWTProcessor<SecurityContext> processor =
        new JwtProcessorFactory().createJwtProcessor(config);
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("adapstory-bc10-service")
            .issuer("https://auth.dev.adapstory.com/realms/adapstory")
            .audience(List.of("account", "adapstory-bc10-service"))
            .expirationTime(new Date(System.currentTimeMillis() + 60_000))
            .claim("plugin_id", "adapstory.ai.course-generator")
            .claim("adapstory_tenant_id", "00000000-0000-4000-a000-000000000001")
            .claim("permissions", List.of("dify-plugin:mcp", "edu-knowledge-graph:mcp"))
            .build();

    assertThatThrownBy(() -> processor.getJWTClaimsSetVerifier().verify(claims, null))
        .hasMessageContaining("aud");
  }
}
