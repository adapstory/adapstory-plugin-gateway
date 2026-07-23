package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.mcpgrant.DelegatedCapabilityAuthority;
import com.adapstory.gateway.mcpgrant.McpAccessTokenContext;
import com.adapstory.gateway.mcpgrant.McpGrantAuthorization;
import com.adapstory.gateway.mcpgrant.McpGrantService;
import com.adapstory.gateway.mcpgrant.McpGrantStorageException;
import com.adapstory.gateway.mcpgrant.ProviderBindingGrant;
import com.adapstory.gateway.util.DelegatedAuthorityHeaders;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@DisplayName("Capability-bound MCP authorization filter")
class PluginMcpJwtClaimFilterTest {

  private static final String PATH = "/internal/plugins/v1/ai-methodist/mcp";
  private static final Instant EXPIRY = Instant.parse("2026-07-16T12:05:00Z");

  private ObjectMapper objectMapper;
  private SimpleMeterRegistry meterRegistry;
  private McpGrantService grantService;
  private PluginMcpJwtClaimFilter filter;
  private FilterChain chain;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
    meterRegistry = new SimpleMeterRegistry();
    grantService = mock(McpGrantService.class);
    filter = new PluginMcpJwtClaimFilter(objectMapper, meterRegistry, grantService, 65536);
    chain = mock(FilterChain.class);
  }

  @Test
  @DisplayName("allows tools/list only for a route present in the token-bound grant")
  void should_allow_tools_list_for_bound_route() throws Exception {
    var request = request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    addSessionHeaders(request);
    var response = new MockHttpServletResponse();
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));

    filter.doFilterInternal(request, response, chain);

    verify(chain)
        .doFilter(
            org.mockito.ArgumentMatchers.any(HttpServletRequest.class),
            org.mockito.ArgumentMatchers.same(response));
    assertThat(request.getAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR))
        .isEqualTo("tenant-123");
  }

  @Test
  @DisplayName("allows tools/call only for the exact provider tool name")
  void should_allow_exact_tool_call_and_preserve_body() throws Exception {
    String body =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"search_methodology_rag\",\"arguments\":{}}}";
    var request = request(body);
    addSessionHeaders(request);
    var response = new MockHttpServletResponse();
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));
    ArgumentCaptor<HttpServletRequest> forwarded =
        ArgumentCaptor.forClass(HttpServletRequest.class);

    filter.doFilterInternal(request, response, chain);

    verify(chain).doFilter(forwarded.capture(), org.mockito.ArgumentMatchers.same(response));
    assertThat(
            new String(
                forwarded.getValue().getInputStream().readAllBytes(), StandardCharsets.UTF_8))
        .isEqualTo(body);
  }

  @Test
  @DisplayName("derives trusted route-scoped delegated authority from stored grant")
  void should_derive_trusted_delegated_authority_from_stored_grant() throws Exception {
    String body =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"n8n__get_workflow_status\",\"arguments\":{}}}";
    var request = new MockHttpServletRequest("POST", "/internal/plugins/v1/n8n-plugin/mcp");
    request.setContent(body.getBytes(StandardCharsets.UTF_8));
    request.setContentType("application/json");
    request.setAttribute(McpGrantJwtAuthenticationFilter.MCP_ACCESS_TOKEN_ATTR, token());
    request.addHeader(DelegatedAuthorityHeaders.HEADER_CAPABILITIES, "automation.workflow.trigger");
    addSessionHeaders(request);
    var response = new MockHttpServletResponse();
    var authority =
        new DelegatedCapabilityAuthority(
            UUID.fromString("00000000-0000-4000-a000-000000000101"),
            "runtime-smoke",
            UUID.fromString("00000000-0000-4000-a000-000000000201"),
            "workflow-delivery@1.0.0",
            List.of("automation.workflow.status", "automation.workflow.trigger"));
    var authorization =
        new McpGrantAuthorization(
            "tenant-123",
            "actor-456",
            EXPIRY,
            List.of(
                new ProviderBindingGrant(
                    "automation.workflow.status",
                    "n8n-plugin",
                    "n8n__get_workflow_status",
                    "2026.07.2",
                    "v1",
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "tenant-service-jwt",
                    "CORE",
                    "tenant",
                    "available",
                    Instant.parse("2026-07-16T12:00:00Z"),
                    "Read one tenant-owned durable workflow task status without provider data.")),
            authority);
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization));

    filter.doFilterInternal(request, response, chain);

    verify(chain)
        .doFilter(
            org.mockito.ArgumentMatchers.any(HttpServletRequest.class),
            org.mockito.ArgumentMatchers.same(response));
    assertThat(request.getAttribute(DelegatedAuthorityHeaders.TRUSTED_RUN_ID_ATTR))
        .isEqualTo("00000000-0000-4000-a000-000000000101");
    assertThat(request.getAttribute(DelegatedAuthorityHeaders.TRUSTED_CAPABILITIES_ATTR))
        .isEqualTo("automation.workflow.status");
  }

  @Test
  @DisplayName("denies an adjacent tool exposed by the same provider")
  void should_deny_unbound_tool_on_bound_route() throws Exception {
    var request =
        request(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"methodology_deep_research\",\"arguments\":{}}}");
    var response = new MockHttpServletResponse();
    addSessionHeaders(request);
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("denies MCP methods outside tools/list and tools/call")
  void should_deny_other_json_rpc_method() throws Exception {
    var request = request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}");
    var response = new MockHttpServletResponse();
    addSessionHeaders(request);
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("fails closed when the shared grant is missing")
  void should_deny_missing_shared_grant() throws Exception {
    var request = request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    var response = new MockHttpServletResponse();
    when(grantService.findAuthorization(token())).thenReturn(Optional.empty());

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("returns service unavailable when Redis authorization state cannot be trusted")
  void should_return_503_on_shared_store_failure() throws Exception {
    var request = request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    var response = new MockHttpServletResponse();
    when(grantService.findAuthorization(token()))
        .thenThrow(new McpGrantStorageException("shared authorization unavailable"));

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(503);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("rejects missing validated access-token context")
  void should_reject_missing_token_context() throws Exception {
    var request = new MockHttpServletRequest("POST", PATH);
    request.setContent("{\"method\":\"tools/list\"}".getBytes(StandardCharsets.UTF_8));
    var response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(401);
    verifyNoInteractions(grantService, chain);
  }

  @Test
  @DisplayName("rejects malformed, batched, or oversized JSON-RPC bodies before proxying")
  void should_reject_invalid_or_oversized_body() throws Exception {
    var malformed = request("[]");
    var malformedResponse = new MockHttpServletResponse();
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));

    filter.doFilterInternal(malformed, malformedResponse, chain);

    assertThat(malformedResponse.getStatus()).isEqualTo(400);
    verifyNoInteractions(chain);

    filter = new PluginMcpJwtClaimFilter(objectMapper, meterRegistry, grantService, 16);
    var oversized = request("{\"method\":\"tools/list\"}");
    var oversizedResponse = new MockHttpServletResponse();
    filter.doFilterInternal(oversized, oversizedResponse, chain);
    assertThat(oversizedResponse.getStatus()).isEqualTo(413);
  }

  @Test
  @DisplayName("rejects duplicate or unknown JSON-RPC fields before authorization")
  void should_reject_parser_differential_json() throws Exception {
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));
    var duplicate =
        request(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\","
                + "\"method\":\"tools/call\",\"params\":{\"name\":\"search_methodology_rag\"}}");
    var duplicateResponse = new MockHttpServletResponse();

    filter.doFilterInternal(duplicate, duplicateResponse, chain);

    assertThat(duplicateResponse.getStatus()).isEqualTo(400);
    verifyNoInteractions(chain);

    var unknown =
        request(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\","
                + "\"legacyAuthority\":\"ai-methodist\"}");
    var unknownResponse = new MockHttpServletResponse();
    filter.doFilterInternal(unknown, unknownResponse, chain);
    assertThat(unknownResponse.getStatus()).isEqualTo(400);
  }

  @Test
  @DisplayName("requires canonical request ids and forbids ids on notifications")
  void should_enforce_json_rpc_request_and_notification_ids() throws Exception {
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));
    var missingId = request("{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}");
    addSessionHeaders(missingId);
    var missingIdResponse = new MockHttpServletResponse();

    filter.doFilterInternal(missingId, missingIdResponse, chain);

    assertThat(missingIdResponse.getStatus()).isEqualTo(400);
    verifyNoInteractions(chain);

    var notificationWithId =
        request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"notifications/initialized\"}");
    addSessionHeaders(notificationWithId);
    var notificationWithIdResponse = new MockHttpServletResponse();

    filter.doFilterInternal(notificationWithId, notificationWithIdResponse, chain);

    assertThat(notificationWithIdResponse.getStatus()).isEqualTo(400);
    verifyNoInteractions(chain);
  }

  @Test
  @DisplayName("accepts canonical cancellation notifications without widening tool authority")
  void should_accept_canonical_cancellation_notification() throws Exception {
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));
    var request =
        request(
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\","
                + "\"params\":{\"requestId\":1,\"reason\":\"superseded\"}}");
    addSessionHeaders(request);
    var response = new MockHttpServletResponse();

    filter.doFilterInternal(request, response, chain);

    verify(chain)
        .doFilter(
            org.mockito.ArgumentMatchers.any(HttpServletRequest.class),
            org.mockito.ArgumentMatchers.same(response));
  }

  @Test
  @DisplayName("uses bounded outcome and reason metric labels rather than provider slugs")
  void should_emit_bounded_metric_labels() throws Exception {
    var request =
        request(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"other_tool\"}}");
    var response = new MockHttpServletResponse();
    addSessionHeaders(request);
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));

    filter.doFilterInternal(request, response, chain);

    var meter = meterRegistry.find("plugin_gateway_mcp_authorization_total").counter();
    assertThat(meter).isNotNull();
    assertThat(meter.getId().getTag("outcome")).isEqualTo("denied");
    assertThat(meter.getId().getTag("reason")).isEqualTo("tool_not_bound");
    assertThat(meter.getId().getTag("slug")).isNull();
  }

  @Test
  @DisplayName("filters only the canonical versioned MCP provider route")
  void should_filter_only_canonical_provider_route() {
    assertThat(filter.shouldNotFilter(new MockHttpServletRequest("POST", PATH))).isFalse();
    assertThat(
            filter.shouldNotFilter(new MockHttpServletRequest("POST", "/internal/mcp-grants/v1")))
        .isTrue();
    assertThat(
            filter.shouldNotFilter(
                new MockHttpServletRequest("POST", "/internal/plugins/ai-methodist/mcp")))
        .isTrue();
  }

  @Test
  @DisplayName("allows initialize without a session for a grant-bound provider route")
  void should_allow_initialize_without_session() throws Exception {
    var request =
        request(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                + "\"params\":{\"protocolVersion\":\"2025-11-25\","
                + "\"capabilities\":{},\"clientInfo\":{\"name\":\"runtime\","
                + "\"version\":\"1.0\"}}}");
    var response = new MockHttpServletResponse();
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));

    filter.doFilterInternal(request, response, chain);

    verify(chain)
        .doFilter(
            org.mockito.ArgumentMatchers.any(HttpServletRequest.class),
            org.mockito.ArgumentMatchers.same(response));
    assertThat(request.getAttribute(PluginMcpJwtClaimFilter.MCP_METHOD_ATTR))
        .isEqualTo("initialize");
  }

  @Test
  @DisplayName("allows GET SSE and DELETE only with a canonical stateful session")
  void should_allow_get_and_delete_with_session() throws Exception {
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));
    for (String method : List.of("GET", "DELETE")) {
      var request = sessionRequest(method);
      var response = new MockHttpServletResponse();

      filter.doFilterInternal(request, response, chain);

      verify(chain).doFilter(request, response);
      assertThat(request.getAttribute(PluginMcpJwtClaimFilter.MCP_METHOD_ATTR))
          .isEqualTo(method.equals("GET") ? "stream/get" : "session/delete");
    }
  }

  @Test
  @DisplayName("rejects stateful requests without a session and browser Origin requests")
  void should_reject_missing_session_and_origin() throws Exception {
    when(grantService.findAuthorization(token())).thenReturn(Optional.of(authorization()));
    var missingSession = request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    var missingSessionResponse = new MockHttpServletResponse();

    filter.doFilterInternal(missingSession, missingSessionResponse, chain);

    assertThat(missingSessionResponse.getStatus()).isEqualTo(400);
    verifyNoInteractions(chain);

    var browserRequest = sessionRequest("GET");
    browserRequest.addHeader("Origin", "https://attacker.example");
    var browserResponse = new MockHttpServletResponse();

    filter.doFilterInternal(browserRequest, browserResponse, chain);

    assertThat(browserResponse.getStatus()).isEqualTo(403);
    verifyNoInteractions(chain);
  }

  private static MockHttpServletRequest request(String body) {
    var request = new MockHttpServletRequest("POST", PATH);
    request.setContent(body.getBytes(StandardCharsets.UTF_8));
    request.setContentType("application/json");
    request.setAttribute(McpGrantJwtAuthenticationFilter.MCP_ACCESS_TOKEN_ATTR, token());
    return request;
  }

  private static MockHttpServletRequest sessionRequest(String method) {
    var request = new MockHttpServletRequest(method, PATH);
    request.setAttribute(McpGrantJwtAuthenticationFilter.MCP_ACCESS_TOKEN_ATTR, token());
    addSessionHeaders(request);
    if (method.equals("GET")) {
      request.addHeader("Accept", "text/event-stream");
      request.addHeader("Last-Event-ID", "event-1");
    }
    return request;
  }

  private static void addSessionHeaders(MockHttpServletRequest request) {
    request.addHeader("Mcp-Session-Id", "session-123");
    request.addHeader("MCP-Protocol-Version", "2025-11-25");
  }

  private static McpAccessTokenContext token() {
    return new McpAccessTokenContext(
        "token-jti", "actor-456", "tenant-123", "agent-runtime", EXPIRY);
  }

  private static McpGrantAuthorization authorization() {
    return new McpGrantAuthorization(
        "tenant-123",
        "actor-456",
        EXPIRY,
        List.of(
            new ProviderBindingGrant(
                "knowledge.source.search",
                "ai-methodist",
                "search_methodology_rag",
                "2026.07.1",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "tenant-service-jwt",
                "CORE",
                "tenant",
                "available",
                Instant.parse("2026-07-16T12:00:00Z"),
                "Search the tenant methodology knowledge base. Use only for grounded sources.")));
  }
}
