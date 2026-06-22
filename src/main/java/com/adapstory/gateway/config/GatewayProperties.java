package com.adapstory.gateway.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Конфигурация Plugin Gateway. */
@Validated
@ConfigurationProperties(prefix = "gateway")
public record GatewayProperties(
    JwtConfig jwt,
    Map<String, String> routes,
    PermissionsConfig permissions,
    PermissionCacheConfig permissionCache,
    InstalledCacheConfig installedCache,
    WebhookConfig webhook,
    Bc02Config bc02,
    McpConfig mcp) {

  public GatewayProperties {
    if (mcp == null) {
      mcp = new McpConfig(8000, "plugin-%s.plugins.svc.cluster.local", 30000, List.of());
    }
  }

  public record JwtConfig(
      @NotBlank String jwksUri,
      @NotBlank String issuer,
      @NotBlank String audience,
      @Positive int jwksCacheTtlMinutes) {}

  public record PermissionsConfig(Map<String, Map<String, String>> routeMappings) {}

  public record PermissionCacheConfig(@Positive int ttlMinutes, @NotBlank String keyPrefix) {}

  /**
   * L-4: Rely on @Positive for validation (fails fast on invalid config). Removed compact
   * constructor defaults — invalid values should fail at startup, not silently default.
   */
  public record InstalledCacheConfig(@Positive int ttlMinutes, @Positive int negativeTtlSeconds) {}

  public record WebhookConfig(
      int retryMaxAttempts,
      long retryInitialIntervalMs,
      double retryMultiplier,
      int pluginPodPort,
      String pluginPodHostTemplate,
      String internalSecret) {

    public WebhookConfig {
      if (pluginPodHostTemplate == null || pluginPodHostTemplate.isBlank()) {
        pluginPodHostTemplate = "plugin-%s";
      }
    }
  }

  /** Конфигурация подключения к BC-02 (Plugin Lifecycle) для запроса manifest permissions. */
  public record Bc02Config(@NotBlank String baseUrl) {}

  /**
   * Конфигурация MCP-маршрутизации к plugin backend.
   *
   * @param pluginPodPort порт plugin pod (e.g., 8000)
   * @param pluginHostTemplate шаблон DNS-имени plugin pod (e.g.,
   *     "plugin-%s.plugins.svc.cluster.local")
   * @param connectTimeoutMs таймаут подключения к plugin backend (ms)
   */
  public record McpConfig(
      @Positive int pluginPodPort,
      @NotBlank String pluginHostTemplate,
      @Positive int connectTimeoutMs,
      List<@Valid PluginRoute> pluginRoutes) {

    public McpConfig {
      if (pluginHostTemplate == null || pluginHostTemplate.isBlank()) {
        pluginHostTemplate = "plugin-%s.plugins.svc.cluster.local";
      }
      if (pluginRoutes == null) {
        pluginRoutes = List.of();
      }
    }
  }

  public record PluginRoute(@NotBlank String slug, @NotBlank String baseUrl) {}
}
