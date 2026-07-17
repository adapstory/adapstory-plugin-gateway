package com.adapstory.gateway.mcpgrant;

import com.adapstory.gateway.dto.GatewayErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Sanitized, typed error boundary for private MCP grant registration. */
@RestControllerAdvice(assignableTypes = McpGrantController.class)
public class McpGrantExceptionHandler {

  /** Maps Lifecycle verification outcomes without exposing provider metadata. */
  @ExceptionHandler(ProviderBindingVerificationException.class)
  public ResponseEntity<GatewayErrorResponse> handleProviderVerification(
      ProviderBindingVerificationException exception, HttpServletRequest request) {
    HttpStatus status =
        switch (exception.reason()) {
          case CONFLICT -> HttpStatus.CONFLICT;
          case INVALID -> HttpStatus.UNPROCESSABLE_ENTITY;
          case UNAVAILABLE -> HttpStatus.SERVICE_UNAVAILABLE;
        };
    return error(
        status, "Provider binding verification failed", exception.reason().name(), request);
  }

  /** Maps token identity, validity, and immutable-binding violations. */
  @ExceptionHandler(McpGrantRejectedException.class)
  public ResponseEntity<GatewayErrorResponse> handleRegistrationRejection(
      McpGrantRejectedException exception, HttpServletRequest request) {
    HttpStatus status =
        switch (exception.reason()) {
          case IDENTITY_MISMATCH -> HttpStatus.FORBIDDEN;
          case TOKEN_VALIDITY -> HttpStatus.UNAUTHORIZED;
          case TOKEN_ALREADY_BOUND -> HttpStatus.CONFLICT;
        };
    return error(status, "MCP grant registration rejected", exception.reason().name(), request);
  }

  /** Maps Redis failures to a retryable, fail-closed response. */
  @ExceptionHandler(McpGrantStorageException.class)
  public ResponseEntity<GatewayErrorResponse> handleStorage(
      McpGrantStorageException exception, HttpServletRequest request) {
    return error(
        HttpStatus.SERVICE_UNAVAILABLE,
        "Shared MCP authorization is unavailable",
        "STORAGE_UNAVAILABLE",
        request);
  }

  /** Maps strict JSON or DTO validation failures to an unprocessable registration. */
  @ExceptionHandler({
    IllegalArgumentException.class,
    HttpMessageNotReadableException.class,
    MethodArgumentNotValidException.class
  })
  public ResponseEntity<GatewayErrorResponse> handleInvalidRequest(
      Exception exception, HttpServletRequest request) {
    return error(
        HttpStatus.UNPROCESSABLE_ENTITY,
        "MCP grant registration payload is invalid",
        "INVALID_BINDINGS",
        request);
  }

  private static ResponseEntity<GatewayErrorResponse> error(
      HttpStatus status, String message, String code, HttpServletRequest request) {
    String requestId = request.getHeader("X-Request-Id");
    if (requestId == null || requestId.isBlank()) {
      requestId = com.adapstory.commons.id.Uuid7.randomUuid().toString();
    }
    var body =
        new GatewayErrorResponse(
            Instant.now().toString(),
            status.value(),
            status.getReasonPhrase(),
            message,
            request.getRequestURI(),
            requestId,
            Map.of("code", code));
    return ResponseEntity.status(status).body(body);
  }
}
