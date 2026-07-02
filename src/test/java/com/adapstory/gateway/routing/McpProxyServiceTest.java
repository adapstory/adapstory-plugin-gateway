package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.adapstory.gateway.config.GatewayProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@DisplayName("McpProxyService")
class McpProxyServiceTest {

  @Test
  @DisplayName("should return unknown when MCP body is null or blank")
  void should_returnUnknown_when_bodyMissing() {
    assertThat(McpProxyService.extractMcpMethod(null)).isEqualTo("unknown");
    assertThat(McpProxyService.extractMcpMethod("   ")).isEqualTo("unknown");
  }

  @Test
  @DisplayName("should tag metrics with cached MCP method from JSON request")
  void should_tagMetrics_when_cachedMethodPresent() throws Exception {
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
                    new GatewayProperties.PluginRoute("course-builder", "http://plugin:8000/"))));
    McpProxyTransportPort transport = mock(McpProxyTransportPort.class);
    SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    McpProxyService service = new McpProxyService(properties, transport, meterRegistry);

    MockHttpServletRequest request =
        new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
    request.setContentType("application/json");
    request.setAttribute("mcp.method", "tools/list");
    MockHttpServletResponse response = new MockHttpServletResponse();

    service.executeMcpProxy(
        request, response, "http://plugin-course-builder:8000/mcp", "course-builder", "tenant-1");

    verify(transport)
        .proxy(
            request,
            response,
            java.net.URI.create("http://plugin-course-builder:8000/mcp"),
            "tenant-1");
    assertThat(
            meterRegistry
                .get("plugin_gateway_mcp_method_total")
                .tag("slug", "course-builder")
                .tag("mcp_method", "tools/list")
                .counter()
                .count())
        .isEqualTo(1.0d);
  }
}
