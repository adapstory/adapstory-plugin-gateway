package com.adapstory.gateway.dto;

import java.util.List;

/**
 * DTO для десериализации ответа BC-02 на запрос разрешений плагина.
 *
 * <p>Зеркалит структуру {@code AdapstoryResponse<PluginPermissionScopeListResponse>} из BC-02 для
 * корректного маппинга JSON → Java при вызове {@code GET
 * /api/bc-02/plugin-lifecycle/v1/plugins/{pluginId}/permissions}.
 *
 * @param data содержимое ответа с pluginId и списком scope-имён
 */
public record PluginPermissionsResponse(Data data) {

  /**
   * Вложенные данные ответа.
   *
   * @param pluginId идентификатор плагина
   * @param permissions список scope-имён из запечатанного манифеста
   */
  public record Data(String pluginId, List<String> permissions) {

    /** Compact constructor: defensive copy, null → empty list. */
    public Data {
      permissions = permissions != null ? List.copyOf(permissions) : List.of();
    }
  }
}
