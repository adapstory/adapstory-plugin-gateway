package com.adapstory.gateway.routing;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.adapstory.gateway.filter.PluginMcpJwtClaimFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClient;

/**
 * Тесты McpRouteController: MCP route resolution, proxy dispatch, error handling.
 *
 * <p>Покрывает: successful proxy to plugin /mcp, slug resolution to backend URL, 404 for unknown
 * slug, header forwarding (X-Tenant-Id, X-Request-Id, X-Correlation-Id), 502 for unavailable
 * backend, mcp_method tag extraction.
 */
@DisplayName("McpRouteController")
@Isolated
class McpRouteControllerTest {

  private WireMockServer wireMockServer;
  private McpRouteController controller;
  private ObjectMapper objectMapper;
  private SimpleMeterRegistry meterRegistry;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(0);
    wireMockServer.start();

    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();
    meterRegistry = new SimpleMeterRegistry();

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of("content", "http://localhost:8081"),
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
                30000,
                0,
                86400,
                List.of(
                    new GatewayProperties.PluginRoute(
                        "dify-plugin",
                        "http://dev-dify-plugin-svc.env-dev.svc:8000/",
                        "http://dev-dify-plugin-mcp-headless.env-dev.svc:8000/"))));

    McpProxyService mcpProxyService = buildMcpProxyService(properties);
    controller = new McpRouteController(mcpProxyService, objectMapper, meterRegistry);
  }

  private McpProxyService buildMcpProxyService(GatewayProperties properties) {
    McpSessionAffinityRouter affinityRouter = mock(McpSessionAffinityRouter.class);
    when(affinityRouter.resolve(
            org.mockito.ArgumentMatchers.any(URI.class),
            org.mockito.ArgumentMatchers.nullable(String.class),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.nullable(String.class),
            org.mockito.ArgumentMatchers.nullable(String.class)))
        .thenAnswer(
            invocation ->
                new McpSessionRoute(
                    invocation.getArgument(0, URI.class), invocation.getArgument(3) == null));
    return new McpProxyService(
        properties,
        new RestClientMcpProxyTransport(properties, RestClient.builder(), 0),
        affinityRouter,
        meterRegistry);
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  private static void addEstablishedSessionHeaders(MockHttpServletRequest request) {
    request.addHeader("Mcp-Session-Id", "session-123");
    request.addHeader("MCP-Protocol-Version", "2025-11-25");
  }

  @Nested
  @DisplayName("Successful MCP proxy")
  class SuccessfulProxy {

    @Test
    @DisplayName("should proxy POST /internal/plugins/v1/{slug}/mcp to plugin backend /mcp")
    void should_proxyMcp_when_validSlug() throws Exception {
      // Arrange
      wireMockServer.stubFor(
          post(urlEqualTo("/mcp"))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withHeader("Content-Type", "application/json")
                      .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}")));

      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE");

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/v1/course-builder/mcp");
      request.setContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}".getBytes());
      request.setContentType("application/json");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR, "course-builder");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-1");
      addEstablishedSessionHeaders(request);

      // Override backend URL to WireMock
      controller.overridePluginUrl("course-builder", wireMockServer.baseUrl());

      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      controller.proxyMcp("course-builder", request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).contains("tools");
      wireMockServer.verify(1, postRequestedFor(urlEqualTo("/mcp")));
      var counter =
          meterRegistry.get("plugin_gateway_mcp_proxy_total").tag("status", "success").counter();
      assertThat(counter.getId().getTag("slug")).isNull();
    }

    @Test
    @DisplayName("should forward X-Tenant-Id header to plugin backend")
    void should_forwardTenantId_when_proxying() throws Exception {
      // Arrange
      wireMockServer.stubFor(
          post(urlEqualTo("/mcp")).willReturn(aResponse().withStatus(200).withBody("{}")));

      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-42", List.of("content.read"), "CORE");

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/v1/course-builder/mcp");
      request.setContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}".getBytes());
      request.setContentType("application/json");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR, "course-builder");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-42");
      request.addHeader("x-TeNaNt-iD", "forged-tenant");
      request.addHeader("X-Request-Id", "req-123");
      request.addHeader("X-Correlation-Id", "corr-456");
      addEstablishedSessionHeaders(request);

      controller.overridePluginUrl("course-builder", wireMockServer.baseUrl());
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      controller.proxyMcp("course-builder", request, response);

      // Assert
      wireMockServer.verify(
          postRequestedFor(urlEqualTo("/mcp"))
              .withHeader("X-Tenant-Id", equalTo("tenant-42"))
              .withHeader("X-Request-Id", equalTo("req-123"))
              .withHeader("X-Correlation-Id", equalTo("corr-456")));
      assertThat(wireMockServer.getAllServeEvents().get(0).getRequest().getHeader("X-Tenant-Id"))
          .isEqualTo("tenant-42");
    }

    @Test
    @DisplayName("should not forward Authorization header to plugin backend")
    void should_notForwardAuthHeader_when_proxying() throws Exception {
      // Arrange
      wireMockServer.stubFor(
          post(urlEqualTo("/mcp")).willReturn(aResponse().withStatus(200).withBody("{}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/v1/course-builder/mcp");
      request.setContent("{}".getBytes());
      request.setContentType("application/json");
      request.addHeader("Authorization", "Bearer some-jwt");
      request.setAttribute(
          PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR,
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE"));
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR, "course-builder");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-1");
      addEstablishedSessionHeaders(request);

      controller.overridePluginUrl("course-builder", wireMockServer.baseUrl());
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      controller.proxyMcp("course-builder", request, response);

      // Assert
      wireMockServer.verify(postRequestedFor(urlEqualTo("/mcp")).withoutHeader("Authorization"));
    }
  }

  @Nested
  @DisplayName("Error handling")
  class ErrorHandling {

    @Test
    @DisplayName("returns typed status and bounded metric for session-routing failures")
    void should_map_session_routing_failure_without_provider_cardinality() throws Exception {
      McpProxyService proxyService = mock(McpProxyService.class);
      when(proxyService.resolvePluginMcpUrl("course-builder"))
          .thenReturn("http://course-builder/mcp");
      doThrow(new McpSessionRoutingException(McpSessionRoutingException.Reason.INVALID_SESSION))
          .when(proxyService)
          .executeMcpProxy(
              org.mockito.ArgumentMatchers.any(),
              org.mockito.ArgumentMatchers.any(),
              org.mockito.ArgumentMatchers.anyString(),
              org.mockito.ArgumentMatchers.nullable(String.class),
              org.mockito.ArgumentMatchers.anyString());
      McpRouteController routeController =
          new McpRouteController(proxyService, objectMapper, meterRegistry);
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/v1/course-builder/mcp");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-1");
      MockHttpServletResponse response = new MockHttpServletResponse();

      routeController.proxyMcp("course-builder", request, response);

      assertThat(response.getStatus()).isEqualTo(400);
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Bad Request");
      var counter =
          meterRegistry
              .get("plugin_gateway_mcp_session_routing_total")
              .tag("outcome", "denied")
              .tag("reason", "invalid_session")
              .counter();
      assertThat(counter.count()).isEqualTo(1.0);
      assertThat(counter.getId().getTag("slug")).isNull();
    }

    @Test
    @DisplayName("should return 400 when slug contains invalid characters")
    void should_return400_when_invalidSlug() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/v1/../etc/passwd/mcp");
      request.setContent("{}".getBytes());
      request.setContentType("application/json");
      request.setAttribute(
          PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR,
          new PluginSecurityContext("adapstory.hack", "tenant-1", List.of("content.read"), "CORE"));
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR, "../etc/passwd");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-1");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      controller.proxyMcp("../etc/passwd", request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("should return 502 when plugin backend is unavailable")
    void should_return502_when_backendUnavailable() throws Exception {
      // Arrange — stop WireMock to simulate down backend
      wireMockServer.stop();

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/v1/course-builder/mcp");
      request.setContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}".getBytes());
      request.setContentType("application/json");
      request.setAttribute(
          PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR,
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE"));
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR, "course-builder");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-1");

      controller.overridePluginUrl("course-builder", "http://localhost:1");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      controller.proxyMcp("course-builder", request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(502);
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Bad Gateway");
      assertThat(error.details()).containsEntry("slug", "course-builder");

      // Restart for tearDown
      wireMockServer.start();
    }

    @Test
    @DisplayName("should forward 4xx from plugin backend")
    void should_forward4xx_when_backendReturns4xx() throws Exception {
      // Arrange
      wireMockServer.stubFor(
          post(urlEqualTo("/mcp"))
              .willReturn(
                  aResponse()
                      .withStatus(400)
                      .withHeader("Content-Type", "application/json")
                      .withBody(
                          "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/v1/course-builder/mcp");
      request.setContent("invalid json".getBytes());
      request.setContentType("application/json");
      request.setAttribute(
          PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR,
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE"));
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR, "course-builder");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-1");

      controller.overridePluginUrl("course-builder", wireMockServer.baseUrl());
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      controller.proxyMcp("course-builder", request, response);

      // Assert — 4xx passes through transparently
      assertThat(response.getStatus()).isEqualTo(400);
      assertThat(response.getContentAsString()).contains("Invalid Request");
    }
  }

  @Nested
  @DisplayName("HTTP route contract")
  class HttpRouteContract {

    @Test
    @DisplayName("should proxy GET SSE on the canonical MCP endpoint")
    void should_proxyGetSse_withSessionAndResumeHeaders() throws Exception {
      wireMockServer.stubFor(
          get(urlEqualTo("/mcp"))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withHeader("Content-Type", "text/event-stream")
                      .withHeader("Mcp-Session-Id", "session-123")
                      .withHeader("MCP-Protocol-Version", "2025-11-25")
                      .withBody("id: 2\ndata: {}\n\n")));
      controller.overridePluginUrl("course-builder", wireMockServer.baseUrl());
      MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

      MvcResult pending =
          mockMvc
              .perform(
                  org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(
                          "/internal/plugins/v1/course-builder/mcp")
                      .header("Accept", "text/event-stream")
                      .header("Mcp-Session-Id", "session-123")
                      .header("MCP-Protocol-Version", "2025-11-25")
                      .header("Last-Event-ID", "1"))
              .andExpect(request().asyncStarted())
              .andReturn();

      mockMvc
          .perform(asyncDispatch(pending))
          .andExpect(status().isOk())
          .andExpect(header().string("Mcp-Session-Id", "session-123"))
          .andExpect(header().string("MCP-Protocol-Version", "2025-11-25"));

      wireMockServer.verify(
          getRequestedFor(urlEqualTo("/mcp"))
              .withHeader("Accept", equalTo("text/event-stream"))
              .withHeader("Mcp-Session-Id", equalTo("session-123"))
              .withHeader("MCP-Protocol-Version", equalTo("2025-11-25"))
              .withHeader("Last-Event-ID", equalTo("1")));
    }

    @Test
    @DisplayName("should proxy DELETE without a request body on the canonical MCP endpoint")
    void should_proxyDelete_withoutBody() throws Exception {
      wireMockServer.stubFor(
          delete(urlEqualTo("/mcp"))
              .willReturn(aResponse().withStatus(204).withHeader("Mcp-Session-Id", "session-123")));
      controller.overridePluginUrl("course-builder", wireMockServer.baseUrl());
      MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

      mockMvc
          .perform(
              org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete(
                      "/internal/plugins/v1/course-builder/mcp")
                  .header("Mcp-Session-Id", "session-123")
                  .header("MCP-Protocol-Version", "2025-11-25"))
          .andExpect(status().isNoContent());

      wireMockServer.verify(
          deleteRequestedFor(urlEqualTo("/mcp"))
              .withHeader("Mcp-Session-Id", equalTo("session-123"))
              .withHeader("MCP-Protocol-Version", equalTo("2025-11-25")));
    }

    @Test
    @DisplayName("should preserve session and protocol headers on POST responses")
    void should_preserveMcpResponseHeaders_onPost() throws Exception {
      wireMockServer.stubFor(
          post(urlEqualTo("/mcp"))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withHeader("Content-Type", "application/json")
                      .withHeader("Mcp-Session-Id", "session-123")
                      .withHeader("MCP-Protocol-Version", "2025-11-25")
                      .withBody("{}")));
      controller.overridePluginUrl("course-builder", wireMockServer.baseUrl());
      MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

      mockMvc
          .perform(
              org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(
                      "/internal/plugins/v1/course-builder/mcp")
                  .contentType("application/json")
                  .content("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"))
          .andExpect(status().isOk())
          .andExpect(header().string("Mcp-Session-Id", "session-123"))
          .andExpect(header().string("MCP-Protocol-Version", "2025-11-25"));
    }

    @Test
    @DisplayName("should return 404 for the removed unversioned MCP route")
    void should_return404_forRemovedUnversionedRoute() throws Exception {
      McpProxyService proxyService = mock(McpProxyService.class);
      McpRouteController routeController =
          new McpRouteController(proxyService, objectMapper, meterRegistry);
      MockMvc mockMvc = MockMvcBuilders.standaloneSetup(routeController).build();

      mockMvc
          .perform(
              org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(
                      "/internal/plugins/course-builder/mcp")
                  .contentType("application/json")
                  .content("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"))
          .andExpect(status().isNotFound());
    }
  }

  @Nested
  @DisplayName("Plugin URL resolution")
  class PluginUrlResolution {

    @Test
    @DisplayName("should resolve plugin URL from template")
    void should_resolveUrl_when_validSlug() {
      String url = controller.resolvePluginMcpUrl("course-builder");
      assertThat(url)
          .isEqualTo(
              "http://plugin-course-builder-mcp-headless.plugins.svc.cluster.local:8000/mcp");
    }

    @Test
    @DisplayName("should resolve URL with simple slug")
    void should_resolveUrl_when_simpleSlug() {
      String url = controller.resolvePluginMcpUrl("quiz");
      assertThat(url)
          .isEqualTo("http://plugin-quiz-mcp-headless.plugins.svc.cluster.local:8000/mcp");
    }

    @Test
    @DisplayName("should resolve URL from configured plugin route before template fallback")
    void should_resolveUrl_when_configuredPluginRouteExists() {
      String url = controller.resolvePluginMcpUrl("dify-plugin");
      assertThat(url).isEqualTo("http://dev-dify-plugin-mcp-headless.env-dev.svc:8000/mcp");
    }
  }

  @Nested
  @DisplayName("MCP method tagging")
  class McpMethodTagging {

    @Test
    @DisplayName("should extract tools/list as mcp_method")
    void should_extractToolsList() {
      String method =
          McpRouteController.extractMcpMethod(
              "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
      assertThat(method).isEqualTo("tools/list");
    }

    @Test
    @DisplayName("should extract tools/call as mcp_method")
    void should_extractToolsCall() {
      String method =
          McpRouteController.extractMcpMethod(
              "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}");
      assertThat(method).isEqualTo("tools/call");
    }

    @Test
    @DisplayName("should return 'unknown' for invalid JSON")
    void should_returnUnknown_when_invalidJson() {
      String method = McpRouteController.extractMcpMethod("not json");
      assertThat(method).isEqualTo("unknown");
    }

    @Test
    @DisplayName("should return 'unknown' for missing method field")
    void should_returnUnknown_when_noMethodField() {
      String method = McpRouteController.extractMcpMethod("{\"jsonrpc\":\"2.0\",\"id\":1}");
      assertThat(method).isEqualTo("unknown");
    }
  }
}
