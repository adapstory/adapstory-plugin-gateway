package com.adapstory.gateway.dto;

import java.util.Map;

/**
 * Формат ответа с ошибкой по Pattern 8.
 *
 * @param timestamp время ошибки (ISO-8601)
 * @param status HTTP статус код
 * @param error краткое описание ошибки
 * @param message детальное сообщение
 * @param path путь запроса
 * @param requestId идентификатор запроса
 * @param details дополнительные детали (pluginId, requiredPermission, etc.)
 */
public record GatewayErrorResponse(
    String timestamp,
    int status,
    String error,
    String message,
    String path,
    String requestId,
    Map<String, Object> details) {}
