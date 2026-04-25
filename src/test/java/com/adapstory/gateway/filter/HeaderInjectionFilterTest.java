package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.dto.PluginSecurityContext;
import jakarta.servlet.FilterChain;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Тесты HeaderInjectionFilter: внедрение обязательных заголовков (request-id, correlation-id,
 * user-id).
 *
 * <p>Покрывает: генерацию request-id, проброс correlation-id, user-id из контекста плагина,
 * анонимный user-id, shouldNotFilter, MDC propagation, request wrapper.
 */
@DisplayName("HeaderInjectionFilter")
class HeaderInjectionFilterTest {

  private HeaderInjectionFilter filter;
  private FilterChain filterChain;

  @BeforeEach
  void setUp() {
    filter = new HeaderInjectionFilter();
    filterChain = mock(FilterChain.class);
  }

  @Nested
  @DisplayName("Header injection")
  class HeaderInjection {

    @Test
    @DisplayName("should generate X-Request-Id when not present")
    void should_generateRequestId() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getHeader("X-Request-Id")).isNotNull().isNotBlank();
      assertThat(response.getHeader("X-Response-Id")).isEqualTo(response.getHeader("X-Request-Id"));
      verify(filterChain).doFilter(any(), any());
    }

    @Test
    @DisplayName("should preserve existing X-Request-Id and mirror it to X-Response-Id")
    void should_preserveRequestId_when_present() throws Exception {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader("X-Request-Id", "11111111-2222-4333-8abc-666666666666");
      MockHttpServletResponse response = new MockHttpServletResponse();

      filter.doFilterInternal(request, response, filterChain);

      assertThat(response.getHeader("X-Request-Id"))
          .isEqualTo("11111111-2222-4333-8abc-666666666666");
      assertThat(response.getHeader("X-Response-Id"))
          .isEqualTo("11111111-2222-4333-8abc-666666666666");
    }

    @Test
    @DisplayName("should generate X-Correlation-Id when not present in request")
    void should_generateCorrelationId_when_absent() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getHeader("X-Correlation-Id")).isNotNull().isNotBlank();
    }

    @Test
    @DisplayName("should reuse existing X-Correlation-Id from request")
    void should_reuseCorrelationId_when_present() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader("X-Correlation-Id", "existing-correlation-id");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      assertThat(response.getHeader("X-Correlation-Id")).isEqualTo("existing-correlation-id");
    }

    @Test
    @DisplayName("should generate new correlation-id when existing is blank")
    void should_generateCorrelationId_when_existingIsBlank() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader("X-Correlation-Id", "  ");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — should generate new, not use blank
      assertThat(response.getHeader("X-Correlation-Id")).isNotBlank().isNotEqualTo("  ");
    }
  }

  @Nested
  @DisplayName("User-id resolution")
  class UserIdResolution {

    @Test
    @DisplayName("should set user-id to 'plugin:{pluginId}' when plugin context exists")
    void should_setPluginUserId_when_pluginContextExists() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.assessment.quiz", "tenant-1", List.of("content.read"), "CORE");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — verify via wrapped request passed to filterChain
      ArgumentCaptor<jakarta.servlet.ServletRequest> requestCaptor =
          ArgumentCaptor.forClass(jakarta.servlet.ServletRequest.class);
      verify(filterChain).doFilter(requestCaptor.capture(), any());

      jakarta.servlet.http.HttpServletRequest wrappedRequest =
          (jakarta.servlet.http.HttpServletRequest) requestCaptor.getValue();
      assertThat(wrappedRequest.getHeader("X-User-Id"))
          .isEqualTo("plugin:adapstory.assessment.quiz");
    }

    @Test
    @DisplayName("should preserve incoming user as X-Adapstory-User-Id when plugin context exists")
    void should_preserveIncomingUser_when_pluginContextExists() throws Exception {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(IntegrationHeaders.HEADER_USER_ID, "student-42");
      PluginSecurityContext ctx =
          new PluginSecurityContext(
              "adapstory.assessment.quiz", "tenant-1", List.of("content.read"), "CORE");
      request.setAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR, ctx);
      MockHttpServletResponse response = new MockHttpServletResponse();

      filter.doFilterInternal(request, response, filterChain);

      ArgumentCaptor<jakarta.servlet.ServletRequest> requestCaptor =
          ArgumentCaptor.forClass(jakarta.servlet.ServletRequest.class);
      verify(filterChain).doFilter(requestCaptor.capture(), any());

      jakarta.servlet.http.HttpServletRequest wrappedRequest =
          (jakarta.servlet.http.HttpServletRequest) requestCaptor.getValue();
      assertThat(wrappedRequest.getHeader(IntegrationHeaders.HEADER_USER_ID))
          .isEqualTo("plugin:adapstory.assessment.quiz");
      assertThat(wrappedRequest.getHeader(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID))
          .isEqualTo("student-42");
    }

    @Test
    @DisplayName("should set user-id to 'anonymous' when no plugin context")
    void should_setAnonymousUserId_when_noPluginContext() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      ArgumentCaptor<jakarta.servlet.ServletRequest> requestCaptor =
          ArgumentCaptor.forClass(jakarta.servlet.ServletRequest.class);
      verify(filterChain).doFilter(requestCaptor.capture(), any());

      jakarta.servlet.http.HttpServletRequest wrappedRequest =
          (jakarta.servlet.http.HttpServletRequest) requestCaptor.getValue();
      assertThat(wrappedRequest.getHeader("X-User-Id")).isEqualTo("anonymous");
    }
  }

  @Nested
  @DisplayName("MDC propagation")
  class MdcPropagation {

    @Test
    @DisplayName("should clear MDC after filter execution")
    void should_clearMdc_afterFilter() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — MDC is cleaned up
      assertThat(MDC.get("request-id")).isNull();
      assertThat(MDC.get("correlation-id")).isNull();
      assertThat(MDC.get("user-id")).isNull();
      assertThat(MDC.get("adapstory-user-id")).isNull();
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
    @DisplayName("should filter gateway API paths")
    void should_filter_gatewayApiPaths() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("should filter webhook paths")
    void should_filter_webhookPaths() {
      MockHttpServletRequest request =
          new MockHttpServletRequest("POST", "/api/bc-02/gateway/v1/webhooks/ai-grader");
      assertThat(filter.shouldNotFilter(request)).isFalse();
    }
  }

  @Nested
  @DisplayName("Request wrapper")
  class RequestWrapper {

    @Test
    @DisplayName("should inject headers accessible via getHeader")
    void should_injectHeaders_via_getHeader() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader("X-Custom-Header", "custom-value");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — injected headers + original headers preserved
      ArgumentCaptor<jakarta.servlet.ServletRequest> requestCaptor =
          ArgumentCaptor.forClass(jakarta.servlet.ServletRequest.class);
      verify(filterChain).doFilter(requestCaptor.capture(), any());

      jakarta.servlet.http.HttpServletRequest wrappedRequest =
          (jakarta.servlet.http.HttpServletRequest) requestCaptor.getValue();
      assertThat(wrappedRequest.getHeader("X-Request-Id")).isNotNull();
      assertThat(response.getHeader("X-Response-Id")).isEqualTo(response.getHeader("X-Request-Id"));
      assertThat(wrappedRequest.getHeader("X-Correlation-Id")).isNotNull();
      assertThat(wrappedRequest.getHeader("X-User-Id")).isNotNull();
      assertThat(wrappedRequest.getHeader("X-Custom-Header")).isEqualTo("custom-value");
    }

    @Test
    @DisplayName("should return injected headers via getHeaders(name) method")
    void should_returnInjectedHeaders_via_getHeaders() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert — verify getHeaders(name) returns injected values
      ArgumentCaptor<jakarta.servlet.ServletRequest> requestCaptor =
          ArgumentCaptor.forClass(jakarta.servlet.ServletRequest.class);
      verify(filterChain).doFilter(requestCaptor.capture(), any());

      jakarta.servlet.http.HttpServletRequest wrappedRequest =
          (jakarta.servlet.http.HttpServletRequest) requestCaptor.getValue();
      java.util.List<String> requestIdValues =
          java.util.Collections.list(wrappedRequest.getHeaders("X-Request-Id"));
      assertThat(requestIdValues).hasSize(1).allMatch(v -> !v.isBlank());

      // Non-injected header returns original enumeration
      java.util.List<String> unknownValues =
          java.util.Collections.list(wrappedRequest.getHeaders("X-Unknown"));
      assertThat(unknownValues).isEmpty();
    }

    @Test
    @DisplayName("should include injected header names in getHeaderNames")
    void should_includeInjectedHeaders_in_getHeaderNames() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      filter.doFilterInternal(request, response, filterChain);

      // Assert
      ArgumentCaptor<jakarta.servlet.ServletRequest> requestCaptor =
          ArgumentCaptor.forClass(jakarta.servlet.ServletRequest.class);
      verify(filterChain).doFilter(requestCaptor.capture(), any());

      jakarta.servlet.http.HttpServletRequest wrappedRequest =
          (jakarta.servlet.http.HttpServletRequest) requestCaptor.getValue();
      List<String> headerNames = java.util.Collections.list(wrappedRequest.getHeaderNames());
      assertThat(headerNames).contains("X-Request-Id", "X-Correlation-Id", "X-User-Id");
    }

    @Test
    @DisplayName("should expose X-Adapstory-User-Id when incoming user is preserved")
    void should_includeOriginalActorHeader_when_present() throws Exception {
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader(IntegrationHeaders.HEADER_USER_ID, "user-abc");
      MockHttpServletResponse response = new MockHttpServletResponse();

      filter.doFilterInternal(request, response, filterChain);

      ArgumentCaptor<jakarta.servlet.ServletRequest> requestCaptor =
          ArgumentCaptor.forClass(jakarta.servlet.ServletRequest.class);
      verify(filterChain).doFilter(requestCaptor.capture(), any());

      jakarta.servlet.http.HttpServletRequest wrappedRequest =
          (jakarta.servlet.http.HttpServletRequest) requestCaptor.getValue();
      assertThat(wrappedRequest.getHeader(IntegrationHeaders.HEADER_USER_ID))
          .isEqualTo("anonymous");
      assertThat(wrappedRequest.getHeader(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID))
          .isEqualTo("user-abc");
    }
  }
}
