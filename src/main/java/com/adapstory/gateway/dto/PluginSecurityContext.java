package com.adapstory.gateway.dto;

import java.util.List;

/**
 * Контекст безопасности плагина, извлечённый из JWT claims.
 *
 * @param pluginId идентификатор плагина (e.g., "adapstory.education_module.ai-grader")
 * @param tenantId идентификатор тенанта
 * @param permissions список разрешений плагина (e.g., ["content.read", "submission.read"])
 * @param trustLevel уровень доверия плагина (e.g., "CORE", "COMMUNITY")
 */
public record PluginSecurityContext(
    String pluginId, String tenantId, List<String> permissions, String trustLevel) {}
