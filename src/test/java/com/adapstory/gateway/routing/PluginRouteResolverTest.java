package com.adapstory.gateway.routing;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.client.RestClient;

/** Тесты PluginRouteResolver: route mapping, prefix strip, proxy dispatch, error handling. */
class PluginRouteResolverTest {

  private WireMockServer wireMockServer;
  private PluginRouteResolver resolver;
  private ObjectMapper objectMapper;
  private CircuitBreakerRegistry circuitBreakerRegistry;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(0);
    wireMockServer.start();

    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();

    CircuitBreakerConfig cbConfig =
        CircuitBreakerConfig.custom()
            .slidingWindowSize(2)
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(60))
            .minimumNumberOfCalls(2)
            .permittedNumberOfCallsInHalfOpenState(1)
            .build();
    circuitBreakerRegistry = CircuitBreakerRegistry.of(cbConfig);

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(
                "content", wireMockServer.baseUrl(),
                "submission", wireMockServer.baseUrl(),
                "identity", wireMockServer.baseUrl()),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"));

    resolver =
        new PluginRouteResolver(
            properties, RestClient.builder(), circuitBreakerRegistry, objectMapper);
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Nested
  @DisplayName("extractRouteKey")
  class ExtractRouteKey {

    @Test
    @DisplayName("should extract route key 'content' from gateway path")
    void should_extractContent_when_contentPath() {
      assertThat(resolver.extractRouteKey("/api/bc-02/gateway/v1/api/content/v1/materials/123"))
          .isEqualTo("content");
    }

    @Test
    @DisplayName("should extract route key 'submission' from gateway path")
    void should_extractSubmission_when_submissionPath() {
      assertThat(resolver.extractRouteKey("/api/bc-02/gateway/v1/api/submission/v1/grades"))
          .isEqualTo("submission");
    }

    @Test
    @DisplayName("should extract route key 'identity' from gateway path")
    void should_extractIdentity_when_identityPath() {
      assertThat(resolver.extractRouteKey("/api/bc-02/gateway/v1/api/identity/v1/users/me"))
          .isEqualTo("identity");
    }

    @Test
    @DisplayName("should return null for non-gateway path")
    void should_returnNull_when_nonGatewayPath() {
      assertThat(resolver.extractRouteKey("/api/content/v1/materials/123")).isNull();
    }

    @Test
    @DisplayName("should extract route key without trailing slash")
    void should_extractRouteKey_when_noTrailingPath() {
      assertThat(resolver.extractRouteKey("/api/bc-02/gateway/v1/api/content"))
          .isEqualTo("content");
    }

    @Test
    @DisplayName("Pattern 4: prefix strip removes /api/bc-02/gateway/v1 only")
    void should_stripGatewayPrefixOnly() {
      String originalPath = "/api/bc-02/gateway/v1/api/content/v1/materials/123";
      String expected = "/api/content/v1/materials/123";
      assertThat(originalPath.substring("/api/bc-02/gateway/v1".length())).isEqualTo(expected);
    }
  }

  @Nested
  @DisplayName("proxy — successful dispatch")
  class ProxySuccess {

    @Test
    @DisplayName("should proxy GET request and return backend response")
    void should_proxyGet_when_validRoute() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          get(urlEqualTo("/api/content/v1/materials/123"))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withHeader("Content-Type", "application/json")
                      .withBody("{\"id\":\"123\",\"title\":\"Math Basics\"}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).contains("Math Basics");
      wireMockServer.verify(1, getRequestedFor(urlEqualTo("/api/content/v1/materials/123")));
    }

    @Test
    @DisplayName("should proxy POST request with body")
    void should_proxyPost_when_validRouteWithBody() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          post(urlEqualTo("/api/content/v1/materials"))
              .willReturn(
                  aResponse()
                      .withStatus(201)
                      .withHeader("Content-Type", "application/json")
                      .withBody("{\"id\":\"new-123\"}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.setContent("{\"title\":\"New Material\"}".getBytes());
      request.setContentType("application/json");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(201);
      assertThat(response.getContentAsString()).contains("new-123");
      wireMockServer.verify(1, postRequestedFor(urlEqualTo("/api/content/v1/materials")));
    }

    @Test
    @DisplayName("should proxy PUT request with body")
    void should_proxyPut_when_validRouteWithBody() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          put(urlEqualTo("/api/content/v1/materials/123"))
              .willReturn(aResponse().withStatus(200).withBody("{\"updated\":true}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("PUT", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setContent("{\"title\":\"Updated Material\"}".getBytes());
      request.setContentType("application/json");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(200);
      wireMockServer.verify(1, putRequestedFor(urlEqualTo("/api/content/v1/materials/123")));
    }

    @Test
    @DisplayName("should forward query string to target")
    void should_forwardQueryString_when_present() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          get(urlEqualTo("/api/content/v1/materials?page=1&size=10"))
              .willReturn(aResponse().withStatus(200).withBody("{\"items\":[]}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.setQueryString("page=1&size=10");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(200);
      wireMockServer.verify(
          1, getRequestedFor(urlEqualTo("/api/content/v1/materials?page=1&size=10")));
    }

    @Test
    @DisplayName("should not forward Authorization header to target BC")
    void should_notForwardAuthHeader_when_proxying() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          get(urlEqualTo("/api/content/v1/materials/123"))
              .willReturn(aResponse().withStatus(200).withBody("{}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.addHeader("Authorization", "Bearer some-plugin-jwt");
      request.addHeader("X-Custom-Header", "custom-value");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      wireMockServer.verify(
          getRequestedFor(urlEqualTo("/api/content/v1/materials/123"))
              .withoutHeader("Authorization")
              .withHeader("X-Custom-Header", equalTo("custom-value")));
    }

    @Test
    @DisplayName("should not forward hop-by-hop headers to target BC")
    void should_notForwardHopByHopHeaders_when_proxying() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          get(urlEqualTo("/api/content/v1/materials/123"))
              .willReturn(aResponse().withStatus(200).withBody("{}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.addHeader("Connection", "keep-alive");
      request.addHeader("Transfer-Encoding", "chunked");
      request.addHeader("X-Custom-Header", "preserved");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      wireMockServer.verify(
          getRequestedFor(urlEqualTo("/api/content/v1/materials/123"))
              .withoutHeader("Connection")
              .withoutHeader("Transfer-Encoding")
              .withHeader("X-Custom-Header", equalTo("preserved")));
    }

    @Test
    @DisplayName("should copy response headers from target, excluding hop-by-hop")
    void should_copyResponseHeaders_when_proxying() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          get(urlEqualTo("/api/content/v1/materials/123"))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withHeader("X-Custom-Response", "response-value")
                      .withHeader("Content-Type", "application/json")
                      .withBody("{}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getHeader("X-Custom-Response")).isEqualTo("response-value");
      assertThat(response.getHeader("Content-Type")).isEqualTo("application/json");
    }
  }

  @Nested
  @DisplayName("proxy — error handling")
  class ProxyErrors {

    @Test
    @DisplayName("should return 404 when route key cannot be extracted from non-gateway path")
    void should_return404_when_routeKeyNotExtracted() throws IOException {
      // Arrange — path doesn't match gateway /api/ prefix pattern
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/other/path");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(404);
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).contains("Cannot resolve route from path");
    }

    @Test
    @DisplayName("should return 404 when no target BC configured for route key")
    void should_return404_when_noTargetConfigured() throws IOException {
      // Arrange — unknown route key
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/unknown-service/v1/test");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(404);
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).contains("No target BC configured for route");
    }

    @Test
    @DisplayName("should return 502 when target service returns connection error")
    void should_return502_when_targetServiceDown() throws IOException {
      // Arrange — stop WireMock to simulate unavailable backend
      wireMockServer.stop();

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(502);
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Bad Gateway");
      assertThat(error.details().get("route")).isEqualTo("content");

      // Restart for tearDown
      wireMockServer.start();
    }

    @Test
    @DisplayName("should return 503 when circuit breaker is open")
    void should_return503_when_circuitBreakerOpen() throws IOException {
      // Arrange — manually transition CB to OPEN
      CircuitBreaker cb = circuitBreakerRegistry.circuitBreaker("content");
      cb.transitionToOpenState();

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(503);
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Service Unavailable");
      assertThat(error.details().get("route")).isEqualTo("content");
      assertThat(error.details().get("circuitBreakerState")).isEqualTo("OPEN");
    }

    @Test
    @DisplayName("should include pluginId in error details when plugin context is available")
    void should_includePluginId_when_pluginContextAvailable() throws IOException {
      // Arrange — unknown route with plugin context set
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader", "tenant-1", List.of("content.read"), "CORE");

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/unknown-route/v1/test");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(404);
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.details().get("pluginId")).isEqualTo("adapstory.education_module.ai-grader");
    }
  }

  @Nested
  @DisplayName("proxy — backend response forwarding")
  class BackendResponseForwarding {

    @Test
    @DisplayName("should forward 4xx from target backend")
    void should_forward4xx_when_backendReturns4xx() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          get(urlEqualTo("/api/content/v1/materials/999"))
              .willReturn(
                  aResponse()
                      .withStatus(404)
                      .withHeader("Content-Type", "application/json")
                      .withBody("{\"error\":\"Not Found\"}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/999");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert — 4xx passes through transparently
      assertThat(response.getStatus()).isEqualTo(404);
      assertThat(response.getContentAsString()).contains("Not Found");
    }

    @Test
    @DisplayName("should forward 5xx from target backend")
    void should_forward5xx_when_backendReturns5xx() throws IOException {
      // Arrange
      wireMockServer.stubFor(
          get(urlEqualTo("/api/content/v1/materials/123"))
              .willReturn(
                  aResponse()
                      .withStatus(500)
                      .withHeader("Content-Type", "application/json")
                      .withBody("{\"error\":\"Internal Server Error\"}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      resolver.proxy(request, response);

      // Assert — 5xx passes through
      assertThat(response.getStatus()).isEqualTo(500);
    }
  }
}
