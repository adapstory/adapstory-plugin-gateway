package com.adapstory.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adapstory.commons.header.IntegrationHeaders;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@DisplayName("ProxyHeaderUtils security identity forwarding")
class ProxyHeaderUtilsTest {

  @Test
  @DisplayName("should drop caller-controlled identity headers case-insensitively")
  void should_dropCallerControlledIdentityHeaders_caseInsensitively() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("x-tenant-id", "forged-tenant");
    request.addHeader("X-uSeR-iD", "forged-user");
    request.addHeader("x-adapstory-user-id", "forged-actor");
    request.addHeader("X-PDLC-Run-Id", "forged-run");
    request.addHeader("X-Adapstory-Capability-Grant", "automation.workflow.trigger");
    request.addHeader("X-USER-ROLES", "PLATFORM_ADMIN");

    HttpHeaders outgoing = new HttpHeaders();
    ProxyHeaderUtils.copyRequestHeaders(request, outgoing);

    assertThat(outgoing.get(IntegrationHeaders.HEADER_TENANT_ID)).isNull();
    assertThat(outgoing.get(IntegrationHeaders.HEADER_USER_ID)).isNull();
    assertThat(outgoing.get(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID)).isNull();
    assertThat(outgoing.get(DelegatedAuthorityHeaders.HEADER_RUN_ID)).isNull();
    assertThat(outgoing.get(DelegatedAuthorityHeaders.HEADER_CAPABILITIES)).isNull();
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
    request.setAttribute(
        DelegatedAuthorityHeaders.TRUSTED_RUN_ID_ATTR, "00000000-0000-4000-a000-000000000101");
    request.setAttribute(DelegatedAuthorityHeaders.TRUSTED_NODE_ID_ATTR, "runtime-smoke");
    request.setAttribute(
        DelegatedAuthorityHeaders.TRUSTED_POLICY_VERSION_ATTR, "workflow-delivery@1.0.0");
    request.setAttribute(
        DelegatedAuthorityHeaders.TRUSTED_GRANT_ID_ATTR, "00000000-0000-4000-a000-000000000201");
    request.setAttribute(
        DelegatedAuthorityHeaders.TRUSTED_CAPABILITIES_ATTR, "automation.workflow.status");

    HttpHeaders outgoing = new HttpHeaders();
    ProxyHeaderUtils.copyRequestHeaders(request, outgoing);

    assertThat(outgoing.get(IntegrationHeaders.HEADER_TENANT_ID)).containsExactly("jwt-tenant");
    assertThat(outgoing.get(IntegrationHeaders.HEADER_USER_ID))
        .containsExactly("plugin:ai-course-generator");
    assertThat(outgoing.get(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID))
        .containsExactly("jwt-subject");
    assertThat(outgoing.get("X-User-Roles")).containsExactly("TENANT_OWNER");
    assertThat(outgoing.get(DelegatedAuthorityHeaders.HEADER_RUN_ID))
        .containsExactly("00000000-0000-4000-a000-000000000101");
    assertThat(outgoing.get(DelegatedAuthorityHeaders.HEADER_NODE_ID))
        .containsExactly("runtime-smoke");
    assertThat(outgoing.get(DelegatedAuthorityHeaders.HEADER_POLICY_VERSION))
        .containsExactly("workflow-delivery@1.0.0");
    assertThat(outgoing.get(DelegatedAuthorityHeaders.HEADER_GRANT_ID))
        .containsExactly("00000000-0000-4000-a000-000000000201");
    assertThat(outgoing.get(DelegatedAuthorityHeaders.HEADER_CAPABILITIES))
        .containsExactly("automation.workflow.status");
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

  @Test
  @DisplayName("should close the upstream SSE body immediately when the client disconnects")
  void should_closeUpstreamStream_whenDownstreamWriteFails() throws Exception {
    ClientHttpResponse upstream = mock(ClientHttpResponse.class);
    TrackingInputStream body = new TrackingInputStream("data: {}\n\n".getBytes());
    when(upstream.getStatusCode()).thenReturn(HttpStatus.OK);
    when(upstream.getHeaders()).thenReturn(new HttpHeaders());
    when(upstream.getBody()).thenReturn(body);
    OutputStream disconnectedClient =
        new OutputStream() {
          @Override
          public void write(int value) throws IOException {
            throw new IOException("client disconnected");
          }

          @Override
          public void write(byte[] value, int offset, int length) throws IOException {
            throw new IOException("client disconnected");
          }
        };

    assertThatThrownBy(
            () ->
                ProxyHeaderUtils.copyStreamingResponse(
                    upstream, new MockHttpServletResponse(), disconnectedClient))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("disconnected");
    assertThat(body.closed).isTrue();
  }

  private static final class TrackingInputStream extends ByteArrayInputStream {

    private boolean closed;

    private TrackingInputStream(byte[] bytes) {
      super(bytes);
    }

    @Override
    public void close() throws IOException {
      closed = true;
      super.close();
    }
  }
}
