package com.adapstory.gateway.dto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Тесты GatewayErrorResponse: record DTO для ответов с ошибками Pattern 8.
 *
 * <p>Покрывает: все поля record, empty details, details with values.
 */
@DisplayName("GatewayErrorResponse")
class GatewayErrorResponseTest {

  @Test
  @DisplayName("should create response with all fields")
  void should_createResponse_withAllFields() {
    // Act
    var response =
        new GatewayErrorResponse(
            "2026-03-23T10:00:00Z",
            403,
            "Forbidden",
            "Access denied",
            "/api/bc-02/gateway/v1/api/content",
            "request-id-123",
            Map.of("pluginId", "test-plugin"));

    // Assert
    assertThat(response.timestamp()).isEqualTo("2026-03-23T10:00:00Z");
    assertThat(response.status()).isEqualTo(403);
    assertThat(response.error()).isEqualTo("Forbidden");
    assertThat(response.message()).isEqualTo("Access denied");
    assertThat(response.path()).isEqualTo("/api/bc-02/gateway/v1/api/content");
    assertThat(response.requestId()).isEqualTo("request-id-123");
    assertThat(response.details()).containsEntry("pluginId", "test-plugin");
  }

  @Test
  @DisplayName("should handle empty details map")
  void should_handleEmptyDetails() {
    // Act
    var response =
        new GatewayErrorResponse(
            "2026-03-23T10:00:00Z",
            404,
            "Not Found",
            "Route not found",
            "/unknown",
            "req-id",
            Map.of());

    // Assert
    assertThat(response.details()).isNotNull().isEmpty();
  }
}
