package com.adapstory.gateway.mcpgrant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.dto.McpGrantRegistrationRequest;
import com.adapstory.gateway.dto.ProviderBindingGrantRequest;
import com.adapstory.gateway.filter.HeaderInjectionFilter;
import com.adapstory.gateway.filter.McpGrantJwtAuthenticationFilter;
import com.adapstory.gateway.filter.PluginAuthFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@DisplayName("MCP grant registration endpoint")
class McpGrantControllerTest {

  @Test
  @DisplayName("registers the complete exact binding set and returns empty 204")
  void should_register_exact_bindings_and_return_no_content() {
    McpGrantService service = mock(McpGrantService.class);
    McpGrantController controller = new McpGrantController(service);
    HttpServletRequest servletRequest = mock(HttpServletRequest.class);
    McpAccessTokenContext token =
        new McpAccessTokenContext(
            "token-jti",
            "actor-456",
            "tenant-123",
            "agent-runtime",
            Instant.parse("2026-07-16T12:05:00Z"));
    when(servletRequest.getAttribute(
            com.adapstory.gateway.filter.McpGrantJwtAuthenticationFilter.MCP_ACCESS_TOKEN_ATTR))
        .thenReturn(token);
    when(servletRequest.getAttribute(HeaderInjectionFilter.TRUSTED_TENANT_ID_ATTR))
        .thenReturn("asserted-tenant");
    when(servletRequest.getAttribute(HeaderInjectionFilter.TRUSTED_ADAPSTORY_USER_ID_ATTR))
        .thenReturn("asserted-actor");
    var binding = binding();
    var requestBinding = requestBinding(binding);

    var response =
        controller.register(
            new McpGrantRegistrationRequest(List.of(requestBinding)), servletRequest);

    assertThat(response.getStatusCode().value()).isEqualTo(204);
    assertThat(response.getBody()).isNull();
    verify(service).register(token, "asserted-tenant", "asserted-actor", List.of(binding));
  }

  @Test
  @DisplayName("rejects direct invocation without validated token context")
  void should_reject_missing_validated_token_context() {
    McpGrantController controller = new McpGrantController(mock(McpGrantService.class));

    org.assertj.core.api.Assertions.assertThatThrownBy(
            () ->
                controller.register(
                    new McpGrantRegistrationRequest(List.of(requestBinding(binding()))),
                    mock(HttpServletRequest.class)))
        .isInstanceOf(McpGrantRejectedException.class);
  }

  @Test
  @DisplayName("preserves signed actor identity across the composed header filter")
  void should_preserve_signed_identity_across_header_injection() throws Exception {
    McpGrantService service = mock(McpGrantService.class);
    McpGrantController controller = new McpGrantController(service);
    McpAccessTokenContext token =
        new McpAccessTokenContext(
            "token-jti",
            "actor-456",
            "tenant-123",
            "agent-runtime",
            Instant.parse("2026-07-16T12:05:00Z"));
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setRequestURI("/internal/mcp-grants/v1");
    request.setAttribute(McpGrantJwtAuthenticationFilter.MCP_ACCESS_TOKEN_ATTR, token);
    request.setAttribute(PluginAuthFilter.AUTHENTICATED_ACTOR_ID_ATTR, token.subject());
    MockHttpServletResponse response = new MockHttpServletResponse();
    var registration = new McpGrantRegistrationRequest(List.of(requestBinding(binding())));

    new HeaderInjectionFilter()
        .doFilter(
            request,
            response,
            (wrapped, ignored) -> controller.register(registration, (HttpServletRequest) wrapped));

    verify(service).register(token, "tenant-123", "actor-456", List.of(binding()));
  }

  private static ProviderBindingGrant binding() {
    return new ProviderBindingGrant(
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
        "Search the tenant methodology knowledge base. Use only for grounded sources.");
  }

  private static ProviderBindingGrantRequest requestBinding(ProviderBindingGrant binding) {
    return new ProviderBindingGrantRequest(
        binding.capability(),
        binding.routeSlug(),
        binding.toolName(),
        binding.toolVersion(),
        binding.inputSchemaVersion(),
        binding.inputSchemaDigest(),
        binding.authPolicy(),
        binding.trustLevel(),
        binding.tenantVisibility(),
        binding.status(),
        binding.lastValidatedAt(),
        binding.description());
  }
}
