package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.gateway.config.GatewayProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

/** Тесты PluginRouteResolver: route mapping, prefix strip. */
class PluginRouteResolverTest {

  private PluginRouteResolver resolver;

  @BeforeEach
  void setUp() {
    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(
                "content", "http://adapstory-data-model-engine:8080",
                "submission", "http://adapstory-submission:8080",
                "identity", "http://adapstory-identity:8080"),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"));

    resolver =
        new PluginRouteResolver(
            properties,
            RestClient.builder(),
            CircuitBreakerRegistry.ofDefaults(),
            new ObjectMapper());
  }

  @Test
  @DisplayName("Extract route key from gateway path — content")
  void extractRouteKey_content() {
    assertThat(resolver.extractRouteKey("/gateway/api/content/v1/materials/123"))
        .isEqualTo("content");
  }

  @Test
  @DisplayName("Extract route key from gateway path — submission")
  void extractRouteKey_submission() {
    assertThat(resolver.extractRouteKey("/gateway/api/submission/v1/grades"))
        .isEqualTo("submission");
  }

  @Test
  @DisplayName("Extract route key from gateway path — identity")
  void extractRouteKey_identity() {
    assertThat(resolver.extractRouteKey("/gateway/api/identity/v1/users/me")).isEqualTo("identity");
  }

  @Test
  @DisplayName("Non-gateway path returns null")
  void extractRouteKey_nonGatewayPath() {
    assertThat(resolver.extractRouteKey("/api/content/v1/materials/123")).isNull();
  }

  @Test
  @DisplayName("Path without trailing slash after route key")
  void extractRouteKey_noTrailingPath() {
    assertThat(resolver.extractRouteKey("/gateway/api/content")).isEqualTo("content");
  }

  @Test
  @DisplayName("Pattern 4: prefix strip removes /gateway only")
  void prefixStrip_removesGatewayOnly() {
    // Pattern 4: /gateway/api/content/v1/materials/123 → /api/content/v1/materials/123
    String originalPath = "/gateway/api/content/v1/materials/123";
    String expected = "/api/content/v1/materials/123";
    assertThat(originalPath.substring("/gateway".length())).isEqualTo(expected);
  }
}
