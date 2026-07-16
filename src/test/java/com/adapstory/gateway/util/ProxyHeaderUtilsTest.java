package com.adapstory.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.commons.header.IntegrationHeaders;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

@DisplayName("ProxyHeaderUtils security identity forwarding")
class ProxyHeaderUtilsTest {

  @Test
  @DisplayName("should drop caller-controlled identity headers case-insensitively")
  void should_dropCallerControlledIdentityHeaders_caseInsensitively() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("x-tenant-id", "forged-tenant");
    request.addHeader("X-uSeR-iD", "forged-user");
    request.addHeader("x-adapstory-user-id", "forged-actor");
    request.addHeader("X-USER-ROLES", "PLATFORM_ADMIN");

    HttpHeaders outgoing = new HttpHeaders();
    ProxyHeaderUtils.copyRequestHeaders(request, outgoing);

    assertThat(outgoing.get(IntegrationHeaders.HEADER_TENANT_ID)).isNull();
    assertThat(outgoing.get(IntegrationHeaders.HEADER_USER_ID)).isNull();
    assertThat(outgoing.get(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID)).isNull();
    assertThat(outgoing.get("X-User-Roles")).isNull();
  }

  @Test
  @DisplayName("should re-add only trusted wrapper identity values under canonical names")
  void should_reAddOnlyTrustedWrapperIdentityValues() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("x-tenant-id", "forged-tenant");
    request.addHeader("X-uSeR-iD", "forged-user");
    request.addHeader("X-USER-ROLES", "PLATFORM_ADMIN");
    request.setAttribute("trustedTenantId", "jwt-tenant");
    request.setAttribute("trustedUserId", "plugin:ai-course-generator");
    request.setAttribute("trustedAdapstoryUserId", "jwt-subject");
    request.setAttribute("trustedUserRoles", "TENANT_OWNER");

    HttpHeaders outgoing = new HttpHeaders();
    ProxyHeaderUtils.copyRequestHeaders(request, outgoing);

    assertThat(outgoing.get(IntegrationHeaders.HEADER_TENANT_ID)).containsExactly("jwt-tenant");
    assertThat(outgoing.get(IntegrationHeaders.HEADER_USER_ID))
        .containsExactly("plugin:ai-course-generator");
    assertThat(outgoing.get(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID))
        .containsExactly("jwt-subject");
    assertThat(outgoing.get("X-User-Roles")).containsExactly("TENANT_OWNER");
  }

  @Test
  @DisplayName("should preserve replay and SSE cursor headers while replacing identity")
  void should_preserveReplayAndEventCursorHeaders() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Idempotency-Key", "00000000-0000-4000-8000-000000000001");
    request.addHeader("X-Fingerprint", "deterministic-test-fingerprint");
    request.addHeader("Last-Event-ID", "174-0");

    HttpHeaders outgoing = new HttpHeaders();
    ProxyHeaderUtils.copyRequestHeaders(request, outgoing);

    assertThat(outgoing.get("X-Idempotency-Key"))
        .containsExactly("00000000-0000-4000-8000-000000000001");
    assertThat(outgoing.get("X-Fingerprint")).containsExactly("deterministic-test-fingerprint");
    assertThat(outgoing.get("Last-Event-ID")).containsExactly("174-0");
  }
}
