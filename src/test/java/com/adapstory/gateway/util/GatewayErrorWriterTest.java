package com.adapstory.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Тесты GatewayErrorWriter: стандартизированные ошибки Gateway в формате Pattern 8.
 *
 * <p>Покрывает: корректный JSON-ответ, статус код, content-type, request-id extraction, committed
 * response, details map.
 */
@DisplayName("GatewayErrorWriter")
class GatewayErrorWriterTest {

  private ObjectMapper objectMapper;

  @BeforeEach
  void setUp() {
    objectMapper =
        com.fasterxml.jackson.databind.json.JsonMapper.builder().findAndAddModules().build();
  }

  @Nested
  @DisplayName("writeError")
  class WriteError {

    @Test
    @DisplayName("should write error response with correct status and content-type")
    void should_writeErrorResponse_withCorrectStatusAndContentType() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      GatewayErrorWriter.writeError(
          objectMapper, response, request, 403, "Forbidden", "Access denied", Map.of());

      // Assert
      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.getContentType()).isEqualTo("application/json");
    }

    @Test
    @DisplayName("should include correct fields in JSON response")
    void should_includeCorrectFields_inJsonResponse() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          403,
          "Forbidden",
          "Plugin does not have permission",
          Map.of("pluginId", "test-plugin", "requiredPermission", "content.read"));

      // Assert
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.status()).isEqualTo(403);
      assertThat(error.error()).isEqualTo("Forbidden");
      assertThat(error.message()).isEqualTo("Plugin does not have permission");
      assertThat(error.path()).isEqualTo("/api/bc-02/gateway/v1/api/content/v1/materials");
      assertThat(error.timestamp()).isNotNull();
      assertThat(error.requestId()).isNotNull();
      assertThat(error.details()).containsEntry("pluginId", "test-plugin");
      assertThat(error.details()).containsEntry("requiredPermission", "content.read");
    }

    @Test
    @DisplayName("should use X-Request-Id header when present")
    void should_useRequestIdHeader_when_present() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      request.addHeader("X-Request-Id", "custom-request-id-123");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      GatewayErrorWriter.writeError(
          objectMapper, response, request, 500, "Internal Server Error", "Error", Map.of());

      // Assert
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.requestId()).isEqualTo("custom-request-id-123");
    }

    @Test
    @DisplayName("should generate UUID request-id when header not present")
    void should_generateRequestId_when_headerAbsent() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      GatewayErrorWriter.writeError(
          objectMapper, response, request, 404, "Not Found", "Route not found", Map.of());

      // Assert
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.requestId()).isNotNull().isNotBlank();
    }

    @Test
    @DisplayName("should not write when response is already committed")
    void should_notWrite_when_responseCommitted() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();
      response.getOutputStream().write("already committed".getBytes());
      response.flushBuffer(); // commits the response

      int statusBefore = response.getStatus();

      // Act
      GatewayErrorWriter.writeError(
          objectMapper, response, request, 500, "Error", "Should not be written", Map.of());

      // Assert — status should not change since response was committed
      assertThat(response.getStatus()).isEqualTo(statusBefore);
    }

    @Test
    @DisplayName("should handle empty details map")
    void should_handleEmptyDetails() throws Exception {
      // Arrange
      MockHttpServletRequest request =
          new MockHttpServletRequest("GET", "/api/bc-02/gateway/v1/api/content/v1/materials");
      MockHttpServletResponse response = new MockHttpServletResponse();

      // Act
      GatewayErrorWriter.writeError(
          objectMapper, response, request, 401, "Unauthorized", "Invalid token", Map.of());

      // Assert
      GatewayErrorResponse error =
          objectMapper.readValue(response.getContentAsString(), GatewayErrorResponse.class);
      assertThat(error.details()).isNotNull().isEmpty();
    }
  }

  @Nested
  @DisplayName("getOrGenerateRequestId")
  class GetOrGenerateRequestId {

    @Test
    @DisplayName("should return header value when present")
    void should_returnHeaderValue_when_present() {
      MockHttpServletRequest request = new MockHttpServletRequest();
      request.addHeader("X-Request-Id", "my-request-id");

      assertThat(GatewayErrorWriter.getOrGenerateRequestId(request)).isEqualTo("my-request-id");
    }

    @Test
    @DisplayName("should generate UUID when header absent")
    void should_generateUuid_when_headerAbsent() {
      MockHttpServletRequest request = new MockHttpServletRequest();

      String result = GatewayErrorWriter.getOrGenerateRequestId(request);
      assertThat(result).isNotNull().isNotBlank();
      // Verify it looks like a UUID
      assertThat(result).matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }
  }
}
