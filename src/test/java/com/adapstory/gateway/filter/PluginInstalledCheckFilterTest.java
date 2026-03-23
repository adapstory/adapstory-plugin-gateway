package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.cache.InstalledPluginCacheService;
import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Тесты PluginInstalledCheckFilter: проверка установки плагина перед маршрутизацией.
 *
 * <p>Покрывает: pass-through без контекста, installed=true, installed=false (404), BC-02
 * unavailable (fail-open), null pluginId/tenantId, shouldNotFilter, IllegalArgumentException
 * (fail-open), метрики.
 */
@DisplayName("PluginInstalledCheckFilter")
class PluginInstalledCheckFilterTest {

  private PluginInstalledCheckFilter filter;
  private InstalledPluginCacheService cacheService;
  private ObjectMapper objectMapper;
  private FilterChain filterChain;
  private SimpleMeterRegistry meterRegistry;

  @BeforeEach
  void setUp() {
    cacheService = mock(InstalledPluginCacheService.class);
    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();
    filterChain = mock(FilterChain.class);
    meterRegistry = new SimpleMeterRegistry();

    filter = new PluginInstalledCheckFilter(cacheService, objectMapper, meterRegistry);
  }

  @Nested
  @DisplayName("Pass-through scenarios")
  class PassThrough {

    @Test
    @DisplayName("should pass through when no plugin security context")
    void should_passThrough_when_noPluginContext() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
      verifyNoInteractions(cacheService);
    }

    @Test
    @DisplayName("should pass through when pluginId is null in context")
    void should_passThrough_when_pluginIdNull() throws Exception {
      // Arrange
      PluginSecurityContext ctx = new PluginSecurityContext(null, "tenant-1", List.of(), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
      verifyNoInteractions(cacheService);
    }

    @Test
    @DisplayName("should pass through when tenantId is null in context")
    void should_passThrough_when_tenantIdNull() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext("adapstory.assessment.quiz", null, List.of(), "CORE");
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
      verifyNoInteractions(cacheService);
    }
  }

  @Nested
  @DisplayName("Installed check results")
  class InstalledCheck {

    private static final String PLUGIN_ID = "adapstory.assessment.quiz";
    private static final String TENANT_ID = "tenant-uuid-1";

    @Test
    @DisplayName("should pass through when plugin is installed")
    void should_passThrough_when_installed() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");
      when(cacheService.isInstalled(any(), any(), any(), any())).thenReturn(Optional.of(true));

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
    @DisplayName("should return 404 when plugin is not installed")
    void should_return404_when_notInstalled() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");
      when(cacheService.isInstalled(any(), any(), any(), any())).thenReturn(Optional.of(false));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verifyNoInteractions(filterChain);
      assertThat(response.getStatus()).isEqualTo(404);

      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.message()).isEqualTo("Plugin is not installed for this tenant");
      assertThat(error.details().get("error_code")).isEqualTo("PLUGIN_NOT_INSTALLED");
      assertThat(error.details().get("plugin_id")).isEqualTo(PLUGIN_ID);
      assertThat(error.details().get("tenant_id")).isEqualTo(TENANT_ID);
    }

    @Test
    @DisplayName("should increment notInstalled metric when plugin not installed")
    void should_incrementMetric_when_notInstalled() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");
      when(cacheService.isInstalled(any(), any(), any(), any())).thenReturn(Optional.of(false));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(meterRegistry.counter("plugin_gateway_not_installed_total").count())
          .isEqualTo(1.0);
    }

    @Test
    @DisplayName("should pass through (fail-open) when BC-02 unavailable")
    void should_passThrough_when_bc02Unavailable() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");
      when(cacheService.isInstalled(any(), any(), any(), any())).thenReturn(Optional.empty());

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
    @DisplayName("should pass through (fail-open) when IllegalArgumentException from cache (H-7)")
    void should_passThrough_when_illegalArgumentException() throws Exception {
      // Arrange
      PluginSecurityContext ctx =
          new PluginSecurityContext(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");
      when(cacheService.isInstalled(any(), any(), any(), any()))
          .thenThrow(new IllegalArgumentException("Invalid key format"));

      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials/123");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      verify(filterChain).doFilter(request, response);
    }
  }

  @Nested
  @DisplayName("shouldNotFilter")
  class ShouldNotFilter {

    @Test
    @DisplayName("should not filter actuator paths")
    void should_notFilter_actuatorPaths() {
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should not filter internal paths")
    void should_notFilter_internalPaths() {
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/internal/ready");
      assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    @DisplayName("should filter gateway API paths")
    void should_filter_gatewayApiPaths() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      assertThat(filter.shouldNotFilter(request)).isFalse();
    }
  }
}
