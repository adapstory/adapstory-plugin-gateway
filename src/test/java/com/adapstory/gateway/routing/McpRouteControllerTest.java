package com.adapstory.gateway.routing;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.adapstory.gateway.filter.PluginMcpJwtClaimFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
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

/**
 * Тесты McpRouteController: MCP route resolution, proxy dispatch, error handling.
 *
 * <p>Покрывает: successful proxy to plugin /mcp, slug resolution to backend URL, 404 for unknown
 * slug, header forwarding (X-Tenant-Id, X-Request-Id, X-Correlation-Id), 502 for unavailable
 * backend, mcp_method tag extraction.
 */
@DisplayName("McpRouteController")
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
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"),
            new GatewayProperties.McpConfig(8000, "plugin-%s.plugins.svc.cluster.local", 30000));

    McpProxyService mcpProxyService =
        new McpProxyService(properties, RestClient.builder(), meterRegistry);
    controller = new McpRouteController(mcpProxyService, objectMapper, meterRegistry);
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Nested
  @DisplayName("Successful MCP proxy")
  class SuccessfulProxy {

    @Test
    @DisplayName("should proxy POST /internal/plugins/{slug}/mcp to plugin backend /mcp")
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
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}".getBytes());
      request.setContentType("application/json");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR, "course-builder");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-1");

      // Override backend URL to WireMock
      controller.overridePluginUrl("course-builder", wireMockServer.baseUrl());

      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      controller.proxyMcp("course-builder", request, response);

      // Assert
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).contains("tools");
      wireMockServer.verify(1, postRequestedFor(urlEqualTo("/mcp")));
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
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}".getBytes());
      request.setContentType("application/json");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR, "course-builder");
      request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, "tenant-42");
      request.addHeader("X-Request-Id", "req-123");
      request.addHeader("X-Correlation-Id", "corr-456");

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
    }

    @Test
    @DisplayName("should not forward Authorization header to plugin backend")
    void should_notForwardAuthHeader_when_proxying() throws Exception {
      // Arrange
      wireMockServer.stubFor(
          post(urlEqualTo("/mcp")).willReturn(aResponse().withStatus(200).withBody("{}")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setContent("{}".getBytes());
      request.setContentType("application/json");
      request.addHeader("Authorization", "Bearer some-jwt");
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

      // Assert
      wireMockServer.verify(postRequestedFor(urlEqualTo("/mcp")).withoutHeader("Authorization"));
    }
  }

  @Nested
  @DisplayName("Error handling")
  class ErrorHandling {

    @Test
    @DisplayName("should return 400 when slug contains invalid characters")
    void should_return400_when_invalidSlug() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/../etc/passwd/mcp");
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
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
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
      assertThat(error.details().get("slug")).isEqualTo("course-builder");

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
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
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
  @DisplayName("Plugin URL resolution")
  class PluginUrlResolution {

    @Test
    @DisplayName("should resolve plugin URL from template")
    void should_resolveUrl_when_validSlug() {
      String url = controller.resolvePluginMcpUrl("course-builder");
      assertThat(url).isEqualTo("http://plugin-course-builder.plugins.svc.cluster.local:8000/mcp");
    }

    @Test
    @DisplayName("should resolve URL with simple slug")
    void should_resolveUrl_when_simpleSlug() {
      String url = controller.resolvePluginMcpUrl("quiz");
      assertThat(url).isEqualTo("http://plugin-quiz.plugins.svc.cluster.local:8000/mcp");
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
