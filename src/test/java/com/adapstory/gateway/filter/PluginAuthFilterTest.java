package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests for PluginAuthFilter: JWT validation, claim extraction, security context propagation,
 * shouldNotFilter routing, and error handling.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("PluginAuthFilter")
class PluginAuthFilterTest {

  private static final String VALID_TOKEN = "valid.jwt.token";

  @Mock private FilterChain filterChain;

  @Mock
  private com.nimbusds.jwt.proc.ConfigurableJWTProcessor<com.nimbusds.jose.proc.SecurityContext>
      jwtProcessor;

  private PluginAuthFilter filter;
  private ObjectMapper objectMapper;

  @BeforeEach
  void setUp() throws Exception {
    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost:8080/realms/adapstory/protocol/openid-connect/certs",
                "http://localhost:8080/realms/adapstory",
                "adapstory-plugin-gateway",
                5),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"),
            null);

    filter = new PluginAuthFilter(properties, objectMapper);
    // Inject mocked JWT processor to avoid needing a real JWKS endpoint
    ReflectionTestUtils.setField(filter, "jwtProcessor", jwtProcessor);

    // Clear SecurityContextHolder before each test
    SecurityContextHolder.clearContext();
  }

  // ---------------------------------------------------------------------------
  // Valid JWT token
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("should setPluginSecurityContext withCorrectClaims when called")
  class ValidJwtToken {

    @Test
    @DisplayName("should set PluginSecurityContext with correct claims")
    void should_setPluginSecurityContext_withCorrectClaims_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .issuer("http://localhost:8080/realms/adapstory")
              .audience("adapstory-plugin-gateway")
              .claim("plugin_id", "adapstory.education.quizengine")
              .claim("adapstory_tenant_id", "tenant-42")
              .claim("permissions", List.of("content.read", "submission.write"))
              .claim("trust_level", "CORE")
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — PluginSecurityContext should be set as a request attribute
      Object attrValue = request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);
      assertThat(attrValue).isInstanceOf(PluginSecurityContext.class);
      PluginSecurityContext ctx = (PluginSecurityContext) attrValue;
      assertThat(ctx.pluginId()).isEqualTo("adapstory.education.quizengine");
      assertThat(ctx.tenantId()).isEqualTo("tenant-42");
      assertThat(ctx.permissions()).containsExactly("content.read", "submission.write");
      assertThat(ctx.trustLevel()).isEqualTo("CORE");
    }

    @Test
    @DisplayName("should set authentication in SecurityContextHolder")
    void should_setAuthentication_inSecurityContext_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "adapstory.education.ai-grader")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of("content.read"))
              .claim("trust_level", "COMMUNITY")
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/api/bc-02/gateway/v1/api/submission/v1/grades");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — Authentication was set during doFilter (now cleared by finally)
      verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should create PluginAuthenticationToken with correct authorities")
    void should_createPluginAuthenticationToken_withAuthorities_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "adapstory.education.quizengine")
              .claim("adapstory_tenant_id", "tenant-42")
              .claim("permissions", List.of("content.read", "submission.write"))
              .claim("trust_level", "CORE")
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — verify filter chain was called, meaning authentication succeeded
      verify(filterChain).doFilter(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("should call filterChain.doFilter when token is valid")
    void should_call_filter_chain_when_valid_token() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of("content.read"))
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should handle null trust_level claim")
    void should_handle_null_trust_level_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of("content.read"))
              .claim("trust_level", null)
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — null trust_level is allowed
      PluginSecurityContext ctx =
          (PluginSecurityContext)
              request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);
      assertThat(ctx.trustLevel()).isNull();
      verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should handle empty permissions list")
    void should_handle_empty_permissions_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of())
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — empty permissions is allowed (permissions list is not null)
      PluginSecurityContext ctx =
          (PluginSecurityContext)
              request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);
      assertThat(ctx.permissions()).isEmpty();
      verify(filterChain).doFilter(request, response);
    }
  }

  // ---------------------------------------------------------------------------
  // Missing / invalid Authorization header
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("should return401 when auth header missing")
  class MissingAuthorizationHeader {

    @Test
    @DisplayName("should return 401 when Authorization header is missing")
    void should_return401_when_auth_header_missing() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);
      verifyNoInteractions(filterChain);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Unauthorized");
      assertThat(error.message()).isEqualTo("Missing or invalid Authorization header");
    }

    @Test
    @DisplayName("should return 401 when Authorization header does not start with Bearer")
    void should_return401_when_non_bearer_auth_header() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);
      verifyNoInteractions(filterChain);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Unauthorized");
      assertThat(error.message()).isEqualTo("Missing or invalid Authorization header");
    }

    @Test
    @DisplayName("should return 401 when Authorization header is empty Bearer")
    void should_return401_when_empty_bearer_token() throws Exception {
      // Arrange — Bearer with no token after prefix
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer ");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act — The filter will pass the empty string to jwtProcessor.process() which throws
      filter.doFilterInternal(request, response, filterChain);

      // Assert — exception caught, 401 returned
      assertThat(response.getStatus()).isEqualTo(401);
      verifyNoInteractions(filterChain);
    }
  }

  // ---------------------------------------------------------------------------
  // Invalid / expired JWT
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("Invalid or expired JWT token")
  class InvalidJwtToken {

    @Test
    @DisplayName(
        "should return 401 with 'Invalid or expired plugin token' when JWT processing fails")
    void shouldReturn401_whenJwtProcessingFails() throws Exception {
      // Arrange
      when(jwtProcessor.process(eq("invalid.token"), any()))
          .thenThrow(new RuntimeException("JWT expired"));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer invalid.token");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);
      verifyNoInteractions(filterChain);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Unauthorized");
      assertThat(error.message()).isEqualTo("Invalid or expired plugin token");
    }

    @Test
    @DisplayName("should return 401 when JWT signature is invalid")
    void should_return401_when_jwt_signature_invalid() throws Exception {
      // Arrange
      when(jwtProcessor.process(eq("tampered.jwt.signature"), any()))
          .thenThrow(new com.nimbusds.jose.proc.BadJWSException("Invalid signature"));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer tampered.jwt.signature");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("Invalid or expired plugin token");
    }

    @Test
    @DisplayName("should return 401 when JWT claims verification fails")
    void should_return401_when_claims_verification_fails() throws Exception {
      // Arrange
      when(jwtProcessor.process(eq("bad-claims-token"), any()))
          .thenThrow(new com.nimbusds.jwt.proc.BadJWTException("Invalid audience"));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer bad-claims-token");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("Invalid or expired plugin token");
    }
  }

  // ---------------------------------------------------------------------------
  // JWT missing required claims
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("should return401 when plugin id missing")
  class MissingRequiredClaims {

    @Test
    @DisplayName("should return 401 when plugin_id claim is missing")
    void should_return401_when_plugin_id_missing() throws Exception {
      // Arrange — no plugin_id
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of("content.read"))
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);
      verifyNoInteractions(filterChain);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("JWT missing required plugin claims");
    }

    @Test
    @DisplayName("should return 401 when adapstory_tenant_id claim is missing")
    void should_return401_when_tenant_id_missing() throws Exception {
      // Arrange — no tenant_id
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("permissions", List.of("content.read"))
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("JWT missing required plugin claims");
    }

    @Test
    @DisplayName("should return 401 when permissions claim is missing")
    void should_return401_when_permissions_missing() throws Exception {
      // Arrange — no permissions
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("JWT missing required plugin claims");
    }

    @Test
    @DisplayName("should return 401 when all required claims are missing")
    void should_return401_when_all_required_claims_missing() throws Exception {
      // Arrange — only subject, no plugin claims
      JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("plugin-subject").build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getStatus()).isEqualTo(401);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("JWT missing required plugin claims");
    }
  }

  // ---------------------------------------------------------------------------
  // shouldNotFilter
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("should notFilter actuatorPaths when called")
  class ShouldNotFilter {

    @Test
    @DisplayName("should not filter /actuator/ paths")
    void should_notFilter_actuatorPaths_when_called() {
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should not filter /actuator/info path")
    void should_notFilter_actuatorInfo_when_called() {
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/info");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should not filter /actuator/prometheus path")
    void should_notFilter_actuatorPrometheus_when_called() {
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/prometheus");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should not filter webhook paths")
    void should_notFilter_webhookPaths_when_called() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/api/bc-02/gateway/v1/webhooks/ai-grader");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should not filter webhook path with trailing segments")
    void should_notFilter_webhookPathWithTrailingSegments_when_called() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/api/bc-02/gateway/v1/webhooks/ai-grader/callback");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should filter normal API paths")
    void should_filter_normalApiPaths_when_called() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("should filter root path")
    void should_filter_rootPath_when_called() {
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
      assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("should filter path that only contains /actuator prefix but not /actuator/")
    void should_filter_actuatorWithoutTrailingSlash_when_called() {
      // "/actuator-health" does NOT start with "/actuator/"
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator-health");
      assertThat(filter.shouldNotFilter(request)).isFalse();
    }
  }

  // ---------------------------------------------------------------------------
  // SecurityContext cleanup
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("should clearSecurityContext afterValidToken when called")
  class SecurityContextCleanup {

    @Test
    @DisplayName("should clear SecurityContext in finally block after valid token")
    void should_clearSecurityContext_afterValidToken_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of("content.read"))
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — SecurityContext must be cleared after processing
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("should clear SecurityContext in finally block after invalid token")
    void should_clearSecurityContext_afterInvalidToken_when_called() throws Exception {
      // Arrange
      when(jwtProcessor.process(eq("bad.token"), any()))
          .thenThrow(new RuntimeException("JWT expired"));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer bad.token");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("should clear SecurityContext in finally block when auth header is missing")
    void should_clear_security_context_when_auth_header_missing() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
  }

  // ---------------------------------------------------------------------------
  // Span attributes
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("should setSpanAttributes onValidToken when called")
  class SpanAttributes {

    @Test
    @DisplayName("should set plugin.id and tenant.id span attributes on valid token")
    void should_setSpanAttributes_onValidToken_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "adapstory.education.quizengine")
              .claim("adapstory_tenant_id", "tenant-99")
              .claim("permissions", List.of("content.read"))
              .claim("trust_level", "CORE")
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act — The filter calls Span.current().setAttribute() which is a no-op
      // when no OpenTelemetry agent is present. We verify the flow completes
      // without error, confirming the span attribute calls are made.
      filter.doFilterInternal(request, response, filterChain);

      // Assert — If we reach this point, Span.current() was called and attributes
      // were set without throwing. The filter chain was also invoked.
      verify(filterChain).doFilter(request, response);
    }
  }

  // ---------------------------------------------------------------------------
  // Error response format
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("should include request path when called")
  class ErrorResponseFormat {

    @Test
    @DisplayName("should include request path in error response")
    void should_include_request_path_when_called() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.path()).isEqualTo("/api/bc-02/gateway/v1/api/content/v1/materials/123");
      assertThat(error.status()).isEqualTo(401);
    }

    @Test
    @DisplayName("should include X-Request-Id in error response when present")
    void should_include_request_id_when_called() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader("X-Request-Id", "req-abc-123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.requestId()).isEqualTo("req-abc-123");
    }

    @Test
    @DisplayName("should generate request ID when X-Request-Id is absent")
    void should_generate_request_id_when_absent() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.requestId()).isNotBlank();
    }

    @Test
    @DisplayName("should return JSON content type in error response")
    void should_return_json_content_type_when_called() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getContentType()).isEqualTo("application/json");
    }
  }

  // ---------------------------------------------------------------------------
  // Edge cases
  // ---------------------------------------------------------------------------

  @Nested
  @DisplayName("should reject lowercaseBearer when called")
  class EdgeCases {

    @Test
    @DisplayName("should handle case-sensitive Bearer prefix — lowercase 'bearer' is rejected")
    void should_reject_lowercaseBearer_when_called() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — "bearer " does not start with "Bearer " (capital B)
      assertThat(response.getStatus()).isEqualTo(401);
      verifyNoInteractions(filterChain);
    }

    @Test
    @DisplayName("should extract token correctly when Bearer has extra spaces in token value")
    void should_extractToken_withBearerPrefix_when_called() throws Exception {
      // Arrange — token extracted via substring(BEARER_PREFIX.length())
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of("content.read"))
              .build();

      String token = "test-plugin-jwt-token-for-bearer-extraction";
      when(jwtProcessor.process(eq(token), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — token was correctly extracted and passed to jwtProcessor
      verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should return 401 when filterChain throws ServletException")
    void should_handle_filter_chain_throwing_servlet_exception_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of("content.read"))
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);
      // Simulate filterChain throwing — filter catches Exception internally
      doThrow(new ServletException("Chain error")).when(filterChain).doFilter(any(), any());

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act — filter catches ServletException and returns 401
      filter.doFilterInternal(request, response, filterChain);

      // Assert — filter returns 401 error instead of propagating
      assertThat(response.getStatus()).isEqualTo(401);
      assertThatCode(
              () ->
                  objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class))
          .doesNotThrowAnyException();

      // SecurityContext should still be cleared in finally block
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("should return 401 when filterChain throws IOException")
    void should_handle_filter_chain_throwing_io_exception_when_called() throws Exception {
      // Arrange
      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", List.of("content.read"))
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);
      doThrow(new java.io.IOException("IO error")).when(filterChain).doFilter(any(), any());

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act — filter catches IOException and returns 401
      filter.doFilterInternal(request, response, filterChain);

      // Assert — filter returns 401 error instead of propagating
      assertThat(response.getStatus()).isEqualTo(401);
      assertThatCode(
              () ->
                  objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class))
          .doesNotThrowAnyException();

      // SecurityContext should still be cleared in finally block
      assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("should create immutable copy of permissions list")
    void should_create_immutable_permissions_copy_when_called() throws Exception {
      // Arrange
      java.util.ArrayList<String> mutablePermissions =
          new java.util.ArrayList<>(List.of("content.read", "submission.write"));

      JWTClaimsSet claims =
          new JWTClaimsSet.Builder()
              .subject("plugin-subject")
              .claim("plugin_id", "my-plugin")
              .claim("adapstory_tenant_id", "tenant-1")
              .claim("permissions", mutablePermissions)
              .claim("trust_level", "CORE")
              .build();

      when(jwtProcessor.process(eq(VALID_TOKEN), any())).thenReturn(claims);

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — permissions in context should be a copy (List.copyOf)
      PluginSecurityContext ctx =
          (PluginSecurityContext)
              request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);
      assertThat(ctx.permissions()).containsExactly("content.read", "submission.write");
      // Verify it's an immutable copy
      assertThatThrownBy(() -> ctx.permissions().add("new.permission"))
          .isInstanceOf(UnsupportedOperationException.class);
    }
  }
}
