package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.config.JwtProcessorFactory;
import com.adapstory.gateway.mcpgrant.McpAccessTokenContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

@DisplayName("Gateway-audience MCP JWT authentication")
class McpGrantJwtAuthenticationFilterTest {

  private static final String TOKEN = "signed.gateway.token";
  private static final String PATH = "/internal/mcp-grants/v1";

  private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
  private FilterChain chain;
  private McpGrantJwtAuthenticationFilter filter;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    jwtProcessor = mock(ConfigurableJWTProcessor.class);
    chain = mock(FilterChain.class);
    filter =
        new McpGrantJwtAuthenticationFilter(
            properties(), new ObjectMapper(), new JwtProcessorFactory(), List.of("agent-runtime"));
    ReflectionTestUtils.setField(filter, "jwtProcessor", jwtProcessor);
  }

  @Test
  @DisplayName("accepts a valid exchanged token and exposes only validated security context")
  void should_accept_valid_exchanged_token() throws Exception {
    when(jwtProcessor.process(eq(TOKEN), any())).thenReturn(claims().build());
    var request = request(PATH);
    var response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, chain);

    assertThat(request.getAttribute(McpGrantJwtAuthenticationFilter.MCP_ACCESS_TOKEN_ATTR))
        .isEqualTo(
            new McpAccessTokenContext(
                "token-jti",
                "actor-456",
                "tenant-123",
                "agent-runtime",
                Instant.parse("2026-07-16T12:05:00Z")));
    assertThat(request.getAttribute(PluginAuthFilter.AUTHENTICATED_ACTOR_ID_ATTR))
        .isEqualTo("actor-456");
    verify(chain).doFilter(request, response);
  }

  @Test
  @DisplayName("rejects the removed plugin_tools compatibility claim")
  void should_reject_legacy_plugin_tools_claim() throws Exception {
    when(jwtProcessor.process(eq(TOKEN), any()))
        .thenReturn(claims().claim("plugin_tools", List.of("ai-methodist")).build());
    var request = request(PATH);
    var response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(401);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("rejects token exchange performed by an unauthorized OAuth client")
  void should_reject_untrusted_authorized_party() throws Exception {
    when(jwtProcessor.process(eq(TOKEN), any()))
        .thenReturn(claims().claim("azp", "untrusted-client").build());
    var request = request(PATH);
    var response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("rejects caller-controlled tenant or actor headers that differ from signed claims")
  void should_reject_identity_header_mismatch() throws Exception {
    when(jwtProcessor.process(eq(TOKEN), any())).thenReturn(claims().build());
    var request = request(PATH);
    request.removeHeader("X-User-Id");
    request.addHeader("X-User-Id", "service:another-client");
    var response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("rejects missing security-critical claims even after signature validation")
  void should_reject_missing_jti() throws Exception {
    when(jwtProcessor.process(eq(TOKEN), any()))
        .thenReturn(
            new JWTClaimsSet.Builder()
                .subject("actor-456")
                .expirationTime(Date.from(Instant.parse("2026-07-16T12:05:00Z")))
                .claim("adapstory_tenant_id", "tenant-123")
                .claim("azp", "agent-runtime")
                .build());
    var request = request(PATH);
    var response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(401);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("propagates downstream failures instead of disguising them as JWT failures")
  void should_propagate_downstream_failure() throws Exception {
    when(jwtProcessor.process(eq(TOKEN), any())).thenReturn(claims().build());
    var request = request(PATH);
    var response = new MockHttpServletResponse();
    doThrow(new ServletException("downstream failure")).when(chain).doFilter(request, response);

    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> filter.doFilterInternal(request, response, chain))
        .isInstanceOf(ServletException.class)
        .hasMessageContaining("downstream failure");
  }

  @Test
  @DisplayName("filters only the grant endpoint and canonical MCP provider route")
  void should_filter_only_capability_grant_surface() {
    assertThat(filter.shouldNotFilter(new MockHttpServletRequest("POST", PATH))).isFalse();
    assertThat(
            filter.shouldNotFilter(
                new MockHttpServletRequest("POST", "/internal/plugins/v1/ai-methodist/mcp")))
        .isFalse();
    assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", "/actuator/health")))
        .isTrue();
  }

  private static JWTClaimsSet.Builder claims() {
    return new JWTClaimsSet.Builder()
        .jwtID("token-jti")
        .subject("actor-456")
        .expirationTime(Date.from(Instant.parse("2026-07-16T12:05:00Z")))
        .claim("adapstory_tenant_id", "tenant-123")
        .claim("azp", "agent-runtime");
  }

  private static MockHttpServletRequest request(String path) {
    var request = new MockHttpServletRequest("POST", path);
    request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + TOKEN);
    request.addHeader("X-Tenant-Id", "tenant-123");
    request.addHeader("X-User-Id", "service:agent-runtime");
    request.addHeader("X-Adapstory-User-Id", "actor-456");
    return request;
  }

  private static GatewayProperties properties() {
    return new GatewayProperties(
        new GatewayProperties.JwtConfig(
            "http://localhost:8080/realms/adapstory/protocol/openid-connect/certs",
            "http://localhost:8080/realms/adapstory",
            "adapstory-plugin-gateway",
            5),
        Map.of(),
        Map.of(),
        new GatewayProperties.PermissionsConfig(Map.of()),
        new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
        new GatewayProperties.InstalledCacheConfig(5, 30),
        new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
        new GatewayProperties.Bc02Config("http://localhost:8081"),
        null);
  }
}
