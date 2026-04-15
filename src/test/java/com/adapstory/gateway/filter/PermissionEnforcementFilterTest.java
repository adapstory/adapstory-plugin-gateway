package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.cache.PermissionCacheService;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Тесты PermissionEnforcementFilter: intersection model (SEC-3.2). JWT claims AND manifest
 * permissions must both contain the required permission.
 */
class PermissionEnforcementFilterTest {

  private PermissionEnforcementFilter filter;
  private ObjectMapper objectMapper;
  private FilterChain filterChain;
  private PermissionCacheService cacheService;
  private SimpleMeterRegistry meterRegistry;

  @BeforeEach
  void setUp() {
    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();
    filterChain = mock(FilterChain.class);
    cacheService = mock(PermissionCacheService.class);
    meterRegistry = new SimpleMeterRegistry();

    Map<String, Map<String, String>> routeMappings =
        Map.of(
            "content",
            Map.of("GET", "content.read", "POST", "content.write"),
            "submission",
            Map.of("GET", "submission.read", "POST", "submission.write"));

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            new GatewayProperties.PermissionsConfig(routeMappings),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"),
            null);

    filter = new PermissionEnforcementFilter(properties, objectMapper, cacheService, meterRegistry);
  }

  @Nested
  @DisplayName("should passThrough when permissionInBoth")
  class IntersectionModel {

    @Test
    @DisplayName("Permission in JWT AND manifest — request passes through")
    void should_passThrough_when_permissionInBoth() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader",
              "tenant-1",
              List.of("content.read", "submission.read"),
              "CORE");

      when(cacheService.getCachedPermissions(ctx.pluginId()))
          .thenReturn(Optional.of(List.of("content.read", "submission.read")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("Permission in JWT but NOT in manifest — 403 ADAP-SEC-0010 (revoked)")
    void should_revoked_when_returns403() throws Exception {
      // Arrange — JWT has content.read, but manifest does NOT
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader",
              "tenant-1",
              List.of("content.read", "submission.read"),
              "CORE");

      when(cacheService.getCachedPermissions(ctx.pluginId()))
          .thenReturn(Optional.of(List.of("submission.read"))); // content.read revoked in manifest

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(403);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("Permission 'content.read' has been revoked");
      assertThat(error.details().get("errorCode")).isEqualTo("ADAP-SEC-0010");
      assertThat(error.details().get("pluginId")).isEqualTo("adapstory.education_module.ai-grader");

      assertThat(
              meterRegistry
                  .counter(
                      "plugin_gateway_permission_denied_total",
                      "pluginId",
                      "adapstory.education_module.ai-grader",
                      "errorCode",
                      "ADAP-SEC-0010")
                  .count())
          .isEqualTo(1.0);
    }

    @Test
    @DisplayName("Permission NOT in JWT — 403 (existing behavior, no manifest check needed)")
    void should_return403_when_permissionNotInJwt() throws Exception {
      // Arrange — JWT doesn't have submission.write at all
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader",
              "tenant-1",
              List.of("content.read", "submission.read"),
              "CORE");

      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/api/bc-02/gateway/v1/api/submission/v1/grades");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(403);
      // No manifest check should have happened
      verifyNoInteractions(cacheService);
    }

    @Test
    @DisplayName("Cache miss → BC-02 fetch success → allowed")
    void should_allowed_when_bc02Success() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader", "tenant-1", List.of("content.read"), "CORE");

      when(cacheService.getCachedPermissions(ctx.pluginId())).thenReturn(Optional.empty());
      when(cacheService.fetchAndCachePermissions(ctx.pluginId()))
          .thenReturn(Optional.of(List.of("content.read")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("Cache miss → BC-02 unavailable → 503 ADAP-SEC-0011 (fail-closed)")
    void should_return503_when_bc02Unavailable() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader", "tenant-1", List.of("content.read"), "CORE");

      when(cacheService.getCachedPermissions(ctx.pluginId())).thenReturn(Optional.empty());
      when(cacheService.fetchAndCachePermissions(ctx.pluginId())).thenReturn(Optional.empty());

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(503);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("Unable to verify plugin permissions");
      assertThat(error.details().get("errorCode")).isEqualTo("ADAP-SEC-0011");

      assertThat(
              meterRegistry
                  .counter(
                      "plugin_gateway_permission_unavailable_total",
                      "pluginId",
                      "adapstory.education_module.ai-grader")
                  .count())
          .isEqualTo(1.0);
    }

    @Test
    @DisplayName("Empty manifest permissions — 403 for any permission (AC #7)")
    void should_return403_when_emptyManifestPermissions() throws Exception {
      // Arrange — JWT has content.read, but manifest is empty
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader", "tenant-1", List.of("content.read"), "CORE");

      when(cacheService.getCachedPermissions(ctx.pluginId())).thenReturn(Optional.of(List.of()));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(403);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.details().get("errorCode")).isEqualTo("ADAP-SEC-0010");
    }
  }

  @Nested
  @DisplayName("should passThrough when noPluginContext")
  class NonIntersection {

    @Test
    @DisplayName("No plugin context — passes through (unauthenticated path)")
    void should_passThrough_when_noPluginContext() throws Exception {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      filter.doFilterInternal(request, response, filterChain);

      verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("Non-gateway path should not be filtered")
    void should_not_filter_when_nonGatewayPath() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/webhooks/test");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @ParameterizedTest(name = "[{index}] {0} {1} → {2}")
    @CsvSource(
        delimiter = '|',
        quoteCharacter = '"',
        nullValues = {"NULL"},
        textBlock =
            """
      /api/bc-02/gateway/v1/api/content/v1/materials|GET|content.read
      /api/bc-02/gateway/v1/api/content/v1/materials|POST|content.write
      /api/bc-02/gateway/v1/api/submission/v1/grades|POST|submission.write
      /api/bc-02/gateway/v1/api/content|GET|content.read
      /api/bc-02/gateway/v1/api/unknown/v1/test|GET|NULL
      /api/content/v1/materials|GET|NULL
      /api/bc-02/gateway/v1/api/content/v1/materials|DELETE|NULL
      """)
    @DisplayName("should return expected permission when resolving path and method")
    void should_returnExpectedPermission_when_resolvingPathAndMethod(
        String path, String method, String expectedPermission) {
      String actual = filter.resolveRequiredPermission(path, method);

      if (expectedPermission == null) {
        assertThat(actual)
            .as("resolveRequiredPermission('%s', '%s') should return null", path, method)
            .isNull();
      } else {
        assertThat(actual)
            .as(
                "resolveRequiredPermission('%s', '%s') should return %s",
                path, method, expectedPermission)
            .isEqualTo(expectedPermission);
      }
    }

    @Test
    @DisplayName("No permission mapping for route — 403 with 'No permission mapping' message")
    void should_return403_when_noPermissionMapping() throws Exception {
      // Arrange — plugin has permissions, but the route has no mapping in config
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader", "tenant-1", List.of("content.read"), "CORE");

      MockHttpServletRequest request =
          new MockHttpServletRequest(
              "DELETE", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(403);
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).contains("No permission mapping configured");
    }

    @Test
    @DisplayName("Cache hit increments cache_hit metric")
    void should_incrementMetric_when_cacheHit() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.education_module.ai-grader", "tenant-1", List.of("content.read"), "CORE");

      when(cacheService.getCachedPermissions(ctx.pluginId()))
          .thenReturn(Optional.of(List.of("content.read")));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(
              meterRegistry
                  .counter(
                      "plugin_gateway_permission_cache_hit_total",
                      "pluginId",
                      "adapstory.education_module.ai-grader")
                  .count())
          .isEqualTo(1.0);
    }
  }
}
