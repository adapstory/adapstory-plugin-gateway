package com.adapstory.gateway.dto;

/**
 * DTO ответа от BC-02 на проверку установки плагина.
 *
 * <p>H-5: InstalledPluginFetchClient currently uses JsonNode parsing (not this DTO) because BC-02
 * wraps the response in AdapstoryResponse envelope. Using typed deserialization would require an
 * intermediate wrapper type. Kept for future refactoring to typed RestClient deserialization.
 *
 * @param installed true если плагин установлен
 * @param version установленная версия (null если не установлен)
 */
public record PluginInstalledResponse(boolean installed, String version) {}
