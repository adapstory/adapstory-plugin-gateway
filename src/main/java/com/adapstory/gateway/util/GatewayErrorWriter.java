package com.adapstory.gateway.util;

import com.adapstory.gateway.dto.GatewayErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.MediaType;

/**
 * Утилита для записи стандартизированных ошибок Gateway в формате Pattern 8.
 *
 * <p>Используется фильтрами и контроллерами для единообразного формирования ответов с ошибками.
 */
public final class GatewayErrorWriter {

  private GatewayErrorWriter() {}

  /**
   * Write a standardized error response in Pattern 8 format.
   *
   * @param objectMapper Jackson mapper for serialization
   * @param response servlet response
   * @param request servlet request (for path and request-id extraction)
   * @param status HTTP status code
   * @param error short error label (e.g., "Forbidden")
   * @param message detailed error message
   * @param details additional context (pluginId, requiredPermission, etc.)
   */
  public static void writeError(
      ObjectMapper objectMapper,
      HttpServletResponse response,
      HttpServletRequest request,
      int status,
      String error,
      String message,
      Map<String, Object> details)
      throws IOException {
    if (response.isCommitted()) {
      return;
    }

    GatewayErrorResponse errorResponse =
        new GatewayErrorResponse(
            Instant.now().toString(),
            status,
            error,
            message,
            request.getRequestURI(),
            getOrGenerateRequestId(request),
            details);

    response.setStatus(status);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    objectMapper.writeValue(response.getOutputStream(), errorResponse);
  }

  /** Extract X-Request-Id header or generate a new UUID. */
  public static String getOrGenerateRequestId(HttpServletRequest request) {
    String requestId = request.getHeader("X-Request-Id");
    return requestId != null ? requestId : UUID.randomUUID().toString();
  }
}
