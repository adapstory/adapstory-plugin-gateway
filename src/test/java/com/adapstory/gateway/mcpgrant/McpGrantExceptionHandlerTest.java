package com.adapstory.gateway.mcpgrant;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

@DisplayName("MCP grant typed error mapping")
class McpGrantExceptionHandlerTest {

  private final McpGrantExceptionHandler handler = new McpGrantExceptionHandler();
  private final HttpServletRequest request = request();

  @Test
  @DisplayName("maps provider ambiguity, metadata drift, and dependency loss distinctly")
  void should_map_lifecycle_verification_reasons() {
    assertThat(
            handler
                .handleProviderVerification(
                    new ProviderBindingVerificationException(
                        ProviderBindingVerificationException.Reason.CONFLICT),
                    request)
                .getStatusCode()
                .value())
        .isEqualTo(409);
    assertThat(
            handler
                .handleProviderVerification(
                    new ProviderBindingVerificationException(
                        ProviderBindingVerificationException.Reason.INVALID),
                    request)
                .getStatusCode()
                .value())
        .isEqualTo(422);
    assertThat(
            handler
                .handleProviderVerification(
                    new ProviderBindingVerificationException(
                        ProviderBindingVerificationException.Reason.UNAVAILABLE),
                    request)
                .getStatusCode()
                .value())
        .isEqualTo(503);
  }

  @Test
  @DisplayName("maps identity, token validity, and token rebinding without leaking details")
  void should_map_registration_rejections() {
    assertThat(
            handler
                .handleRegistrationRejection(
                    new McpGrantRejectedException(
                        McpGrantRejectedException.Reason.IDENTITY_MISMATCH, "secret detail"),
                    request)
                .getStatusCode()
                .value())
        .isEqualTo(403);
    assertThat(
            handler
                .handleRegistrationRejection(
                    new McpGrantRejectedException(
                        McpGrantRejectedException.Reason.TOKEN_VALIDITY, "secret detail"),
                    request)
                .getStatusCode()
                .value())
        .isEqualTo(401);
    var conflict =
        handler.handleRegistrationRejection(
            new McpGrantRejectedException(
                McpGrantRejectedException.Reason.TOKEN_ALREADY_BOUND, "secret detail"),
            request);
    assertThat(conflict.getStatusCode().value()).isEqualTo(409);
    assertThat(conflict.getBody().message()).doesNotContain("secret detail");
  }

  @Test
  @DisplayName("maps Redis loss to 503 and malformed registration JSON to 422")
  void should_map_storage_and_payload_failures() {
    assertThat(
            handler
                .handleStorage(new McpGrantStorageException("redis secret"), request)
                .getStatusCode()
                .value())
        .isEqualTo(503);
    assertThat(
            handler
                .handleInvalidRequest(new IllegalArgumentException("bad"), request)
                .getStatusCode()
                .value())
        .isEqualTo(422);
  }

  private static HttpServletRequest request() {
    var request = new MockHttpServletRequest("POST", "/internal/mcp-grants/v1");
    request.addHeader("X-Request-Id", "11111111-2222-4333-8abc-666666666666");
    return request;
  }
}
