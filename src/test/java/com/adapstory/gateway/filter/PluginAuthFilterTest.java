package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import jakarta.servlet.FilterChain;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

/** Тесты PluginAuthFilter: valid JWT, expired JWT, missing claims. */
class PluginAuthFilterTest {

  private static WireMockServer wireMockServer;
  private static RSAKey rsaKey;
  private static JWSSigner signer;

  private PluginAuthFilter filter;
  private ObjectMapper objectMapper;
  private FilterChain filterChain;

  @BeforeAll
  static void setupJwks() throws Exception {
    rsaKey = new RSAKeyGenerator(2048).keyID("test-key-id").generate();
    signer = new RSASSASigner(rsaKey);

    wireMockServer = new WireMockServer(0);
    wireMockServer.start();

    String jwksJson = new JWKSet(rsaKey.toPublicJWK()).toString();
    wireMockServer.stubFor(WireMock.get("/certs").willReturn(WireMock.okJson(jwksJson)));
  }

  @AfterAll
  static void stopWireMock() {
    wireMockServer.stop();
  }

  @BeforeEach
  void setUp() throws Exception {
    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();
    filterChain = mock(FilterChain.class);
    SecurityContextHolder.clearContext();

    GatewayProperties.JwtConfig jwtConfig =
        new GatewayProperties.JwtConfig(
            wireMockServer.baseUrl() + "/certs",
            "https://auth.adapstory.com/realms/plugins",
            "adapstory-core",
            5);

    GatewayProperties properties =
        new GatewayProperties(
            jwtConfig,
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null));

    filter = new PluginAuthFilter(properties, objectMapper);
    filter.init();
  }

  @Test
  @DisplayName("Valid JWT — sets PluginSecurityContext and passes through")
  void validJwt_setsSecurityContextAndPasses() throws Exception {
    // Arrange
    String token =
        buildValidToken(
            "adapstory.education_module.ai-grader",
            "tenant-uuid",
            List.of("content.read", "submission.read"),
            "CORE");

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/gateway/api/content/v1/materials/123");
    request.addHeader("Authorization", "Bearer " + token);
    MockHttpServletResponse response = new MockHttpServletResponse();

    // Act
    filter.doFilterInternal(request, response, filterChain);

    // Assert
    verify(filterChain).doFilter(request, response);

    PluginSecurityContext ctx =
        (PluginSecurityContext) request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);
    assertThat(ctx).isNotNull();
    assertThat(ctx.pluginId()).isEqualTo("adapstory.education_module.ai-grader");
    assertThat(ctx.tenantId()).isEqualTo("tenant-uuid");
    assertThat(ctx.permissions()).containsExactly("content.read", "submission.read");
    assertThat(ctx.trustLevel()).isEqualTo("CORE");
  }

  @Test
  @DisplayName("Expired JWT — returns 401")
  void expiredJwt_returns401() throws Exception {
    // Arrange
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("plugin:test-plugin")
            .issuer("https://auth.adapstory.com/realms/plugins")
            .audience("adapstory-core")
            .claim("plugin_id", "test-plugin")
            .claim("tenant_id", "tenant-1")
            .claim("permissions", List.of("content.read"))
            .claim("trust_level", "CORE")
            .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
            .issueTime(Date.from(Instant.now().minusSeconds(7200)))
            .build();

    SignedJWT signedJWT =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claims);
    signedJWT.sign(signer);

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/gateway/api/content/v1/materials/123");
    request.addHeader("Authorization", "Bearer " + signedJWT.serialize());
    MockHttpServletResponse response = new MockHttpServletResponse();

    // Act
    filter.doFilterInternal(request, response, filterChain);

    // Assert
    assertThat(response.getStatus()).isEqualTo(401);
    GatewayErrorResponse error =
        objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
    assertThat(error.error()).isEqualTo("Unauthorized");
  }

  @Test
  @DisplayName("Missing Authorization header — returns 401")
  void missingAuthHeader_returns401() throws Exception {
    // Arrange
    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/gateway/api/content/v1/materials/123");
    MockHttpServletResponse response = new MockHttpServletResponse();

    // Act
    filter.doFilterInternal(request, response, filterChain);

    // Assert
    assertThat(response.getStatus()).isEqualTo(401);
    GatewayErrorResponse error =
        objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
    assertThat(error.message()).contains("Missing or invalid Authorization header");
  }

  @Test
  @DisplayName("JWT missing required claims — returns 401")
  void jwtMissingClaims_returns401() throws Exception {
    // Arrange — JWT without plugin_id claim
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("plugin:test-plugin")
            .issuer("https://auth.adapstory.com/realms/plugins")
            .audience("adapstory-core")
            .claim("tenant_id", "tenant-1")
            .claim("permissions", List.of("content.read"))
            .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
            .issueTime(Date.from(Instant.now()))
            .build();

    SignedJWT signedJWT =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claims);
    signedJWT.sign(signer);

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/gateway/api/content/v1/materials/123");
    request.addHeader("Authorization", "Bearer " + signedJWT.serialize());
    MockHttpServletResponse response = new MockHttpServletResponse();

    // Act
    filter.doFilterInternal(request, response, filterChain);

    // Assert
    assertThat(response.getStatus()).isEqualTo(401);
  }

  @Test
  @DisplayName("Valid JWT — sets OTLP span attributes plugin.id and tenant.id (AC #3)")
  void validJwt_setsOtlpSpanAttributes() throws Exception {
    // Arrange
    String token =
        buildValidToken(
            "adapstory.education_module.ai-grader",
            "tenant-uuid",
            List.of("content.read"),
            "CORE");

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/gateway/api/content/v1/materials/123");
    request.addHeader("Authorization", "Bearer " + token);
    MockHttpServletResponse response = new MockHttpServletResponse();

    SdkTracerProvider tracerProvider = SdkTracerProvider.builder().build();
    Tracer tracer = tracerProvider.get("test");
    Span span = tracer.spanBuilder("test-filter-otlp").startSpan();

    // Act
    try (Scope scope = span.makeCurrent()) {
      filter.doFilterInternal(request, response, filterChain);
    }
    span.end();
    tracerProvider.close();

    // Assert — ReadableSpan exposes attributes set during filter execution
    ReadableSpan readableSpan = (ReadableSpan) span;
    assertThat(readableSpan.getAttribute(AttributeKey.stringKey("plugin.id")))
        .isEqualTo("adapstory.education_module.ai-grader");
    assertThat(readableSpan.getAttribute(AttributeKey.stringKey("tenant.id")))
        .isEqualTo("tenant-uuid");
  }

  @Test
  @DisplayName("Actuator paths should not be filtered")
  void actuatorPath_shouldNotFilter() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
    assertThat(filter.shouldNotFilter(request)).isTrue();
  }

  @Test
  @DisplayName("Internal paths should not be filtered")
  void internalPath_shouldNotFilter() {
    MockHttpServletRequest request =
        new MockHttpServletRequest("POST", "/internal/webhooks/ai-grader");
    assertThat(filter.shouldNotFilter(request)).isTrue();
  }

  private String buildValidToken(
      String pluginId, String tenantId, List<String> permissions, String trustLevel)
      throws Exception {
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("plugin:" + pluginId)
            .issuer("https://auth.adapstory.com/realms/plugins")
            .audience("adapstory-core")
            .claim("plugin_id", pluginId)
            .claim("tenant_id", tenantId)
            .claim("permissions", permissions)
            .claim("trust_level", trustLevel)
            .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
            .issueTime(Date.from(Instant.now()))
            .build();

    SignedJWT signedJWT =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claims);
    signedJWT.sign(signer);
    return signedJWT.serialize();
  }
}
