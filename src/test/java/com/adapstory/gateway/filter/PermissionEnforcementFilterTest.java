package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.cache.PermissionCacheService;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** Тесты PermissionEnforcementFilter: permission granted, permission denied, cache integration. */
class PermissionEnforcementFilterTest {

  private PermissionEnforcementFilter filter;
  private ObjectMapper objectMapper;
  private FilterChain filterChain;
  private PermissionCacheService cacheService;

  @BeforeEach
  void setUp() {
    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();
    filterChain = mock(FilterChain.class);
    cacheService = mock(PermissionCacheService.class);

    Map<String, Map<String, String>> routeMappings =
        Map.of(
            "content", Map.of("GET", "content.read", "POST", "content.write"),
            "submission", Map.of("GET", "submission.read", "POST", "submission.write"));

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            new GatewayProperties.PermissionsConfig(routeMappings),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null));

    filter = new PermissionEnforcementFilter(properties, objectMapper, cacheService);
  }

  @Test
  @DisplayName("Permission granted — request passes through (cache miss → caches JWT permissions)")
  void permissionGranted_passesThrough() throws Exception {
    // Arrange — explicit cache miss returns null
    when(cacheService.getCachedPermissions(anyString())).thenReturn(null);

    PluginSecurityContext ctx =
        new PluginSecurityContext(
            "adapstory.education_module.ai-grader",
            "tenant-1",
            List.of("content.read", "submission.read"),
            "CORE");

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/gateway/api/content/v1/materials/123");
    request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
    MockHttpServletResponse response = new MockHttpServletResponse();

    // Act
    filter.doFilterInternal(request, response, filterChain);

    // Assert
    verify(filterChain).doFilter(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    verify(cacheService).cachePermissions(ctx.pluginId(), ctx.permissions());
  }

  @Test
  @DisplayName("Permission denied — returns 403 with error details")
  void permissionDenied_returns403() throws Exception {
    // Arrange — cache miss, falls back to JWT permissions
    when(cacheService.getCachedPermissions(anyString())).thenReturn(null);

    // Plugin has content.read, submission.read but NOT submission.write
    PluginSecurityContext ctx =
        new PluginSecurityContext(
            "adapstory.education_module.ai-grader",
            "tenant-1",
            List.of("content.read", "submission.read"),
            "CORE");

    MockHttpServletRequest request =
        new MockHttpServletRequest("POST", "/gateway/api/submission/v1/grades");
    request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
    MockHttpServletResponse response = new MockHttpServletResponse();

    // Act
    filter.doFilterInternal(request, response, filterChain);

    // Assert
    verifyNoInteractions(filterChain);
    assertThat(response.getStatus()).isEqualTo(403);

    GatewayErrorResponse error =
        objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
    assertThat(error.message()).contains("ai-grader");
    assertThat(error.message()).contains("submission.write");
    assertThat(error.details().get("requiredPermission")).isEqualTo("submission.write");
    assertThat(error.details().get("pluginId")).isEqualTo("adapstory.education_module.ai-grader");
  }

  @Test
  @DisplayName("Cache hit — uses cached permissions instead of JWT claims")
  void cacheHit_usesCachedPermissions() throws Exception {
    // Arrange — JWT has content.read but cache says permissions were revoked (empty)
    PluginSecurityContext ctx =
        new PluginSecurityContext(
            "adapstory.education_module.ai-grader",
            "tenant-1",
            List.of("content.read", "submission.read"),
            "CORE");

    when(cacheService.getCachedPermissions(ctx.pluginId())).thenReturn(List.of("submission.read"));

    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/gateway/api/content/v1/materials/123");
    request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
    MockHttpServletResponse response = new MockHttpServletResponse();

    // Act
    filter.doFilterInternal(request, response, filterChain);

    // Assert — cache says no content.read, so 403 even though JWT has it
    verifyNoInteractions(filterChain);
    assertThat(response.getStatus()).isEqualTo(403);
  }

  @Test
  @DisplayName("No plugin context — passes through (unauthenticated path)")
  void noPluginContext_passesThrough() throws Exception {
    // Arrange — no PluginSecurityContext set
    MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/gateway/api/content/v1/materials/123");
    MockHttpServletResponse response = new MockHttpServletResponse();

    // Act
    filter.doFilterInternal(request, response, filterChain);

    // Assert
    verify(filterChain).doFilter(request, response);
  }

  @Test
  @DisplayName("Non-gateway path should not be filtered")
  void nonGatewayPath_shouldNotFilter() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/internal/webhooks/test");
    assertThat(filter.shouldNotFilter(request)).isTrue();
  }

  @Test
  @DisplayName("Route key extraction from path works correctly")
  void routeKeyExtraction() {
    assertThat(filter.resolveRequiredPermission("/gateway/api/content/v1/materials", "GET"))
        .isEqualTo("content.read");
    assertThat(filter.resolveRequiredPermission("/gateway/api/content/v1/materials", "POST"))
        .isEqualTo("content.write");
    assertThat(filter.resolveRequiredPermission("/gateway/api/submission/v1/grades", "POST"))
        .isEqualTo("submission.write");
    assertThat(filter.resolveRequiredPermission("/gateway/api/unknown/v1/test", "GET")).isNull();
  }
}
