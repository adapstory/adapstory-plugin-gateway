package com.adapstory.gateway.routing;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.gateway.config.GatewayProperties;
import com.github.tomakehurst.wiremock.WireMockServer;
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

class FirstPartyPluginRestRouteControllerTest {

  private WireMockServer wireMockServer;
  private FirstPartyPluginRestRouteController controller;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(0);
    wireMockServer.start();

    GatewayProperties properties =
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

    McpProxyService mcpProxyService =
        new McpProxyService(
            properties, null, new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    controller =
        new FirstPartyPluginRestRouteController(
            mcpProxyService,
            new ProxyExecutionService(new RestClientProxyExecutionAdapter(RestClient.builder())),
            CircuitBreakerRegistry.of(
                CircuitBreakerConfig.custom()
                    .slidingWindowSize(2)
                    .minimumNumberOfCalls(2)
                    .failureRateThreshold(50)
                    .waitDurationInOpenState(Duration.ofSeconds(60))
                    .build()),
            tools.jackson.databind.json.JsonMapper.builder().findAndAddModules().build());
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
}
