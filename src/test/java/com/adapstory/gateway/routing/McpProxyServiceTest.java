package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.config.GatewayProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
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
                "plugin-%s-mcp-headless.plugins.svc.cluster.local",
                30000,
                0,
                86400,
                List.of(
                    new GatewayProperties.PluginRoute(
                        "course-builder",
                        "http://plugin:8000/",
                        "http://plugin-mcp-headless:8000/"))));
    McpProxyTransportPort transport = mock(McpProxyTransportPort.class);
    McpSessionAffinityRouter affinityRouter = mock(McpSessionAffinityRouter.class);
    when(affinityRouter.resolve(
            java.net.URI.create("http://plugin-course-builder:8000/mcp"),
            "tenant-1",
            "course-builder",
            null,
            null))
        .thenReturn(
            new McpSessionRoute(
                java.net.URI.create("http://plugin-course-builder:8000/mcp"), false));
    SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    McpProxyService service =
        new McpProxyService(properties, transport, affinityRouter, meterRegistry);

    MockHttpServletRequest request =
        new MockHttpServletRequest("POST", "/internal/plugins/v1/course-builder/mcp");
    request.setContentType("application/json");
    request.setAttribute("mcp.method", "tools/list");
    MockHttpServletResponse response = new MockHttpServletResponse();

    service.executeMcpProxy(
        request, response, "http://plugin-course-builder:8000/mcp", "tenant-1", "course-builder");

    verify(transport)
        .proxy(
            same(request),
            same(response),
            eq(java.net.URI.create("http://plugin-course-builder:8000/mcp")),
            eq("tenant-1"),
            any(McpProxyResponseObserver.class));
    var counter =
        meterRegistry
            .get("plugin_gateway_mcp_method_total")
            .tag("mcp_method", "tools/list")
            .counter();
    assertThat(counter.count()).isEqualTo(1.0d);
    assertThat(counter.getId().getTag("slug")).isNull();
  }

  @Test
  @DisplayName("binds the initialize response session before downstream commit")
  void should_bind_initial_session_before_response_commit() throws Exception {
    McpProxyTransportPort transport = mock(McpProxyTransportPort.class);
    McpSessionAffinityRouter affinityRouter = mock(McpSessionAffinityRouter.class);
    URI endpoint = URI.create("http://10.42.0.8:8000/mcp");
    when(affinityRouter.resolve(
            URI.create("http://headless:8000/mcp"), "tenant-1", "ai-methodist", null, "request-1"))
        .thenReturn(new McpSessionRoute(endpoint, true));
    doAnswer(
            invocation -> {
              McpProxyResponseObserver observer = invocation.getArgument(4);
              HttpHeaders headers = new HttpHeaders();
              headers.set("Mcp-Session-Id", "session-123");
              observer.beforeCommit(HttpStatus.OK, headers, endpoint);
              return null;
            })
        .when(transport)
        .proxy(any(), any(), any(), any(), any());
    McpProxyService service =
        new McpProxyService(properties(), transport, affinityRouter, new SimpleMeterRegistry());
    var request = new MockHttpServletRequest("POST", "/internal/plugins/v1/ai-methodist/mcp");
    request.addHeader("X-Request-Id", "request-1");

    service.executeMcpProxy(
        request,
        new MockHttpServletResponse(),
        "http://headless:8000/mcp",
        "tenant-1",
        "ai-methodist");

    verify(affinityRouter).bind("tenant-1", "ai-methodist", "session-123", endpoint);
  }

  @Test
  @DisplayName("fails closed when initialize succeeds without a canonical session header")
  void should_reject_initialize_response_without_session() throws Exception {
    McpProxyTransportPort transport = mock(McpProxyTransportPort.class);
    McpSessionAffinityRouter affinityRouter = mock(McpSessionAffinityRouter.class);
    URI endpoint = URI.create("http://10.42.0.8:8000/mcp");
    when(affinityRouter.resolve(any(), eq("tenant-1"), eq("ai-methodist"), any(), any()))
        .thenReturn(new McpSessionRoute(endpoint, true));
    doAnswer(
            invocation -> {
              McpProxyResponseObserver observer = invocation.getArgument(4);
              observer.beforeCommit(HttpStatus.OK, new HttpHeaders(), endpoint);
              return null;
            })
        .when(transport)
        .proxy(any(), any(), any(), any(), any());
    McpProxyService service =
        new McpProxyService(properties(), transport, affinityRouter, new SimpleMeterRegistry());

    assertThatThrownBy(
            () ->
                service.executeMcpProxy(
                    new MockHttpServletRequest("POST", "/internal/plugins/v1/ai-methodist/mcp"),
                    new MockHttpServletResponse(),
                    "http://headless:8000/mcp",
                    "tenant-1",
                    "ai-methodist"))
        .isInstanceOf(McpSessionRoutingException.class)
        .extracting(error -> ((McpSessionRoutingException) error).reason())
        .isEqualTo(McpSessionRoutingException.Reason.INVALID_SESSION);
  }

  private static GatewayProperties properties() {
    return new GatewayProperties(
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
            30000,
            0,
            86400,
            List.of()));
  }
}
