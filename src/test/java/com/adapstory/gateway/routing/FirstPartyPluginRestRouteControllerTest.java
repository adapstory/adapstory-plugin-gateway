package com.adapstory.gateway.routing;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.patch;
import static com.github.tomakehurst.wiremock.client.WireMock.patchRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.filter.PluginAuthFilter;
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
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

class FirstPartyPluginRestRouteControllerTest {

  private WireMockServer wireMockServer;
  private FirstPartyPluginRestRouteController controller;
  private McpProxyService mcpProxyService;
  private CircuitBreakerRegistry circuitBreakerRegistry;
  private ObjectMapper objectMapper;
  private GatewayProperties properties;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(0);
    wireMockServer.start();

    properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"),
            new GatewayProperties.McpConfig(
                8000,
                "plugin-%s.plugins.svc.cluster.local",
                30000,
                List.of(
                    new GatewayProperties.PluginRoute(
                        "ai-course-generator", wireMockServer.baseUrl()))));

    mcpProxyService =
        new McpProxyService(
            properties, null, new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    circuitBreakerRegistry =
        CircuitBreakerRegistry.of(
            CircuitBreakerConfig.custom()
                .slidingWindowSize(2)
                .minimumNumberOfCalls(2)
                .failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(60))
                .build());
    controller =
        new FirstPartyPluginRestRouteController(
            mcpProxyService,
            new ProxyExecutionService(new RestClientProxyExecutionAdapter(RestClient.builder())),
            circuitBreakerRegistry,
            objectMapper());
  }

  private FirstPartyPluginRestRouteController newController(
      ProxyExecutionService proxyExecutionService) {
    return new FirstPartyPluginRestRouteController(
        mcpProxyService, proxyExecutionService, circuitBreakerRegistry, objectMapper);
  }

  private ObjectMapper objectMapper() {
    if (objectMapper == null) {
      objectMapper = tools.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();
    }
    return objectMapper;
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Test
  @DisplayName("should proxy first-party plugin REST route to configured backend")
  void should_proxyFirstPartyPluginRestRoute() throws IOException {
    wireMockServer.stubFor(
        get(urlEqualTo("/api/plugins/ai-course-generator/v1/runs?limit=5"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"items\":[]}")));

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/api/plugins/ai-course-generator/v1/runs");
    request.setQueryString("limit=5");
    request.addHeader("Authorization", "Bearer user-token");
    request.addHeader("X-Tenant-Id", "00000000-0000-4000-a000-000000000001");
    MockHttpServletResponse response = new MockHttpServletResponse();

    controller.proxy("ai-course-generator", request, response);

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).contains("\"items\"");
    wireMockServer.verify(
        getRequestedFor(urlEqualTo("/api/plugins/ai-course-generator/v1/runs?limit=5"))
            .withoutHeader("Authorization")
            .withHeader("X-Tenant-Id", equalTo("00000000-0000-4000-a000-000000000001")));
  }

  @Test
  @DisplayName("should proxy PATCH first-party plugin REST route to configured backend")
  void should_proxyPatchFirstPartyPluginRestRoute() throws IOException {
    wireMockServer.stubFor(
        patch(
                urlEqualTo(
                    "/api/plugins/ai-course-generator/v1/runs/019ef1b5-3af7-7861-ac6e-7890b2ec21fa/content"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"saved\":true}")));

    MockHttpServletRequest request =
        new MockHttpServletRequest(
            "PATCH",
            "/api/plugins/ai-course-generator/v1/runs/019ef1b5-3af7-7861-ac6e-7890b2ec21fa/content");
    request.setContentType("application/json");
    request.setContent("{\"blocks\":[{\"text\":\"updated\"}]}".getBytes());
    request.addHeader("Authorization", "Bearer user-token");
    request.addHeader("X-Tenant-Id", "00000000-0000-4000-a000-000000000001");
    MockHttpServletResponse response = new MockHttpServletResponse();

    controller.proxy("ai-course-generator", request, response);

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).contains("\"saved\"");
    wireMockServer.verify(
        patchRequestedFor(
                urlEqualTo(
                    "/api/plugins/ai-course-generator/v1/runs/019ef1b5-3af7-7861-ac6e-7890b2ec21fa/content"))
            .withoutHeader("Authorization")
            .withHeader("X-Tenant-Id", equalTo("00000000-0000-4000-a000-000000000001"))
            .withRequestBody(equalToJson("{\"blocks\":[{\"text\":\"updated\"}]}")));
  }

  @Test
  @DisplayName("should return 400 with plugin slug details when slug is invalid")
  void should_return400_when_slugInvalid() throws IOException {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/plugins/../v1/runs");
    MockHttpServletResponse response = new MockHttpServletResponse();

    controller.proxy("../", request, response);

    GatewayErrorResponse error =
        objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(error.details()).containsEntry("pluginSlug", "../");
  }

  @Test
  @DisplayName("should return 503 with plugin context when circuit breaker is open")
  void should_return503_when_circuitBreakerOpen() throws IOException {
    CircuitBreaker cb = circuitBreakerRegistry.circuitBreaker("plugin-rest:ai-course-generator");
    cb.transitionToOpenState();

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/api/plugins/ai-course-generator/v1/runs");
    request.setAttribute(
        PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR,
        new PluginSecurityContext(
            "adapstory.education.ai-course-generator", "tenant-1", List.of(), "CORE"));
    MockHttpServletResponse response = new MockHttpServletResponse();

    controller.proxy("ai-course-generator", request, response);

    GatewayErrorResponse error =
        objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(error.details())
        .containsEntry("pluginSlug", "ai-course-generator")
        .containsEntry("circuitBreakerState", "OPEN")
        .containsEntry("pluginId", "adapstory.education.ai-course-generator");
  }

  @Test
  @DisplayName("should return 502 with enriched plugin details when proxy execution fails")
  void should_return502_when_proxyExecutionFails() throws IOException {
    ProxyExecutionService failingProxy = mock(ProxyExecutionService.class);
    doThrow(new IOException("boom"))
        .when(failingProxy)
        .executeProxy(
            any(MockHttpServletRequest.class), any(MockHttpServletResponse.class), anyString());
    FirstPartyPluginRestRouteController failingController = newController(failingProxy);

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/api/plugins/ai-course-generator/v1/runs");
    request.setAttribute(
        PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR,
        new PluginSecurityContext(
            "adapstory.education.ai-course-generator", "tenant-1", List.of(), "CORE"));
    MockHttpServletResponse response = new MockHttpServletResponse();

    failingController.proxy("ai-course-generator", request, response);

    GatewayErrorResponse error =
        objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
    assertThat(response.getStatus()).isEqualTo(502);
    assertThat(error.details())
        .containsEntry("pluginSlug", "ai-course-generator")
        .containsEntry("pluginId", "adapstory.education.ai-course-generator");
  }

  @Test
  @DisplayName("should preserve committed response when proxy fails after streaming started")
  void should_preserveCommittedResponse_when_proxyExecutionFailsAfterCommit() throws IOException {
    ProxyExecutionService partiallyCommittedProxy = mock(ProxyExecutionService.class);
    doAnswer(
            invocation -> {
              MockHttpServletResponse response = invocation.getArgument(1);
              response.setStatus(202);
              response.getWriter().write("partial");
              response.flushBuffer();
              throw new IOException("boom");
            })
        .when(partiallyCommittedProxy)
        .executeProxy(
            any(MockHttpServletRequest.class), any(MockHttpServletResponse.class), anyString());
    FirstPartyPluginRestRouteController failingController = newController(partiallyCommittedProxy);

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/api/plugins/ai-course-generator/v1/runs");
    MockHttpServletResponse response = new MockHttpServletResponse();

    failingController.proxy("ai-course-generator", request, response);

    assertThat(response.isCommitted()).isTrue();
    assertThat(response.getStatus()).isEqualTo(202);
    assertThat(response.getContentAsString()).isEqualTo("partial");
  }
}
