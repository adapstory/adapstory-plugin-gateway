package com.adapstory.gateway.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
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
    WebhookConfig webhook,
    Bc02Config bc02) {

  public record JwtConfig(
      @NotBlank String jwksUri,
      @NotBlank String issuer,
      @NotBlank String audience,
      @Positive int jwksCacheTtlMinutes) {}

  public record PermissionsConfig(Map<String, Map<String, String>> routeMappings) {}

  public record PermissionCacheConfig(@Positive int ttlMinutes, @NotBlank String keyPrefix) {}

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
}
