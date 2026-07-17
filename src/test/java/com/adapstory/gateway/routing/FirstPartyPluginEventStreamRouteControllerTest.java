package com.adapstory.gateway.routing;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.adapstory.gateway.config.GatewayProperties;
import com.github.tomakehurst.wiremock.WireMockServer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.client.RestClient;

@Isolated
class FirstPartyPluginEventStreamRouteControllerTest {

  private static final UUID RUN_ID = UUID.fromString("019ef1b5-3af7-7861-ac6e-7890b2ec21fa");
  private static final String TENANT_ID = "00000000-0000-4000-a000-000000000001";

  private WireMockServer wireMockServer;
  private FirstPartyPluginEventStreamRouteController controller;

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
                "plugin-%s-mcp-headless.plugins.svc.cluster.local",
                3000,
                0,
                86400,
                List.of(
                    new GatewayProperties.PluginRoute(
                        "ai-course-generator",
                        wireMockServer.baseUrl(),
                        wireMockServer.baseUrl()))));
    McpProxyService mcpProxyService =
        new McpProxyService(
            properties, null, mock(McpSessionAffinityRouter.class), new SimpleMeterRegistry());
    controller =
        new FirstPartyPluginEventStreamRouteController(
            mcpProxyService, new RestClientEventStreamProxyAdapter(RestClient.builder()));
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Test
  @DisplayName("streams multiple SSE events beyond the ordinary REST read timeout")
  void streamsEventsIncrementally_withoutOrdinaryReadTimeoutOrEnvelope() throws Exception {
    String path = "/api/plugins/ai-course-generator/v1/runs/" + RUN_ID + "/events";
    wireMockServer.stubFor(
        get(urlEqualTo(path))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", MediaType.TEXT_EVENT_STREAM_VALUE)
                    .withHeader("Cache-Control", "no-cache, no-transform")
                    .withHeader("X-Accel-Buffering", "no")
                    .withChunkedDribbleDelay(2, 4_000)
                    .withBody(
                        """
                        id: 1-0
                        event: lesson.completed
                        data: {"lesson_index":1}

                        id: 2-0
                        event: lesson.completed
                        data: {"lesson_index":2}

                        """)));

    MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.addHeader("Authorization", "Bearer browser-token");
    request.addHeader("x-TeNaNt-Id", "forged-tenant");
    request.setAttribute("trustedTenantId", TENANT_ID);
    request.addHeader("Last-Event-ID", "0-0");
    MockHttpServletResponse response = new MockHttpServletResponse();

    var stream = controller.stream(RUN_ID, request, response);
    stream.writeTo(response.getOutputStream());

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentType()).isEqualTo(MediaType.TEXT_EVENT_STREAM_VALUE);
    assertThat(response.getHeader("Cache-Control")).isEqualTo("no-cache, no-transform");
    assertThat(response.getHeader("X-Accel-Buffering")).isEqualTo("no");
    assertThat(response.getContentAsString())
        .contains("id: 1-0", "id: 2-0")
        .doesNotContain("\"data\":{\"data\"");
    wireMockServer.verify(
        getRequestedFor(urlEqualTo(path))
            .withoutHeader("Authorization")
            .withHeader("X-Tenant-Id", equalTo(TENANT_ID))
            .withHeader("Last-Event-ID", equalTo("0-0")));
    assertThat(wireMockServer.getAllServeEvents().get(0).getRequest().getHeader("X-Tenant-Id"))
        .isEqualTo(TENANT_ID);
  }
}
