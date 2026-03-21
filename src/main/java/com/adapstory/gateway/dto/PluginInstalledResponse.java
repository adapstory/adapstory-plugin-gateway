package com.adapstory.gateway.dto;

/**
 * DTO ответа от BC-02 на проверку установки плагина.
 *
 * @param installed true если плагин установлен
 * @param version установленная версия (null если не установлен)
 */
public record PluginInstalledResponse(boolean installed, String version) {}
