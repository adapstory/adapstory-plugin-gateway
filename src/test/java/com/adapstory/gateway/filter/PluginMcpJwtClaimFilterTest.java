package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Тесты PluginMcpJwtClaimFilter: валидация JWT claim plugin_tools для MCP маршрутов.
 *
 * <p>Покрывает: slug extraction, authorized plugin access, unauthorized (403), missing context
 * (401), invalid slug format, shouldNotFilter, metrics.
 */
@DisplayName("PluginMcpJwtClaimFilter")
class PluginMcpJwtClaimFilterTest {

  private PluginMcpJwtClaimFilter filter;
  private ObjectMapper objectMapper;
  private FilterChain filterChain;
  private SimpleMeterRegistry meterRegistry;

  @BeforeEach
  void setUp() {
    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();
    filterChain = mock(FilterChain.class);
    meterRegistry = new SimpleMeterRegistry();

    filter = new PluginMcpJwtClaimFilter(objectMapper, meterRegistry);
  }

  @Nested
  @DisplayName("Authorized MCP access")
  class AuthorizedAccess {

    @Test
    @DisplayName("should pass through when plugin_tools contains the slug")
    void should_passThrough_when_pluginToolsContainsSlug() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(
          PluginMcpJwtClaimFilter.PLUGIN_TOOLS_ATTR, List.of("course-builder", "ai-grader"));
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("should pass through when plugin slug matches single tool")
    void should_passThrough_when_singleToolMatches() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.assessment.quiz", "tenant-1", List.of("submission.read"), "COMMUNITY");
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/quiz/mcp");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.PLUGIN_TOOLS_ATTR, List.of("quiz"));
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
    }
  }

  @Nested
  @DisplayName("Unauthorized MCP access")
  class UnauthorizedAccess {

    @Test
    @DisplayName("should return 403 when plugin_tools does not contain the slug")
    void should_return403_when_slugNotInPluginTools() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.PLUGIN_TOOLS_ATTR, List.of("ai-grader", "quiz"));
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(403);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Forbidden");
      assertThat(error.message()).contains("course-builder");
      assertThat(error.message()).contains("not authorized");
      assertThat(error.details().get("error_code")).isEqualTo("MCP_TOOL_UNAUTHORIZED");
    }

    @Test
    @DisplayName("should return 403 when plugin_tools is empty")
    void should_return403_when_pluginToolsEmpty() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.PLUGIN_TOOLS_ATTR, List.of());
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    @DisplayName("should return 403 when plugin_tools attribute is missing")
    void should_return403_when_pluginToolsAttributeMissing() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      // No PLUGIN_TOOLS_ATTR set
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(403);
    }
  }

  @Nested
  @DisplayName("Missing authentication context")
  class MissingAuthContext {

    @Test
    @DisplayName("should return 401 when no plugin security context")
    void should_return401_when_noPluginContext() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(401);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.error()).isEqualTo("Unauthorized");
      assertThat(error.message()).contains("Authentication required");
    }
  }

  @Nested
  @DisplayName("Slug extraction")
  class SlugExtraction {

    @Test
    @DisplayName("should extract slug from path /internal/plugins/{slug}/mcp")
    void should_extractSlug_when_validPath() {
      assertThat(PluginMcpJwtClaimFilter.extractSlug("/internal/plugins/course-builder/mcp"))
          .isEqualTo("course-builder");
    }

    @Test
    @DisplayName("should extract slug with hyphens and numbers")
    void should_extractSlug_when_containsHyphensAndNumbers() {
      assertThat(PluginMcpJwtClaimFilter.extractSlug("/internal/plugins/ai-grader-v2/mcp"))
          .isEqualTo("ai-grader-v2");
    }

    @Test
    @DisplayName("should return null for non-MCP path")
    void should_returnNull_when_nonMcpPath() {
      assertThat(PluginMcpJwtClaimFilter.extractSlug("/api/bc-02/gateway/v1/api/content/v1/test"))
          .isNull();
    }

    @Test
    @DisplayName("should return null for path missing /mcp suffix")
    void should_returnNull_when_missingMcpSuffix() {
      assertThat(PluginMcpJwtClaimFilter.extractSlug("/internal/plugins/course-builder/other"))
          .isNull();
    }

    @Test
    @DisplayName("should return null for path with missing slug segment")
    void should_returnNull_when_missingSlugSegment() {
      assertThat(PluginMcpJwtClaimFilter.extractSlug("/internal/plugins//mcp")).isNull();
    }
  }

  @Nested
  @DisplayName("shouldNotFilter")
  class ShouldNotFilter {

    @Test
    @DisplayName("should not filter non-MCP paths")
    void should_notFilter_nonMcpPaths() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should not filter actuator paths")
    void should_notFilter_actuatorPaths() {
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should filter MCP paths")
    void should_filter_mcpPaths() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("should not filter webhook paths")
    void should_notFilter_webhookPaths() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/api/bc-02/gateway/v1/webhooks/ai-grader");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }
  }

  @Nested
  @DisplayName("Metrics")
  class Metrics {

    @Test
    @DisplayName("should increment denied counter when slug not in plugin_tools")
    void should_incrementDeniedMetric_when_unauthorized() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.PLUGIN_TOOLS_ATTR, List.of("ai-grader"));
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(
              meterRegistry
                  .counter("plugin_gateway_mcp_denied_total", "slug", "course-builder")
                  .count())
          .isEqualTo(1.0);
    }

    @Test
    @DisplayName("should increment allowed counter when authorized")
    void should_incrementAllowedMetric_when_authorized() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-1", List.of("content.read"), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.PLUGIN_TOOLS_ATTR, List.of("course-builder"));
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(
              meterRegistry
                  .counter("plugin_gateway_mcp_allowed_total", "slug", "course-builder")
                  .count())
          .isEqualTo(1.0);
    }
  }

  @Nested
  @DisplayName("Header propagation")
  class HeaderPropagation {

    @Test
    @DisplayName("should set X-Tenant-Id on request attribute for downstream")
    void should_setTenantId_when_authorized() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education.course-builder", "tenant-42", List.of("content.read"), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/internal/plugins/course-builder/mcp");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      request.setAttribute(PluginMcpJwtClaimFilter.PLUGIN_TOOLS_ATTR, List.of("course-builder"));
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(any(), any());
      assertThat(request.getAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR))
          .isEqualTo("tenant-42");
      assertThat(request.getAttribute(PluginMcpJwtClaimFilter.MCP_PLUGIN_SLUG_ATTR))
          .isEqualTo("course-builder");
    }
  }
}
