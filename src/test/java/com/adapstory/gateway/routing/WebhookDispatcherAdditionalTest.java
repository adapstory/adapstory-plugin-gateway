package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

/**
 * Дополнительные тесты WebhookDispatcher: валидация pluginShortId, internal secret.
 *
 * <p>Покрывает сценарии, не охваченные основным WebhookDispatcherTest: невалидный pluginShortId
 * (400), internal secret verification (403), отсутствие секрета (allowed).
 */
@DisplayName("WebhookDispatcher — additional scenarios")
class WebhookDispatcherAdditionalTest {

  @Nested
  @DisplayName("pluginShortId validation")
  class PluginShortIdValidation {

    @Test
    @DisplayName("should return 400 for pluginShortId with special characters")
    void should_return400_when_pluginShortIdHasSpecialChars() {
      // Arrange
      WebhookDispatcher dispatcher = createDispatcher(null);
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);

      // Act
      ResponseEntity<Void> result =
          dispatcher.dispatchWebhook("../../etc/passwd", payload, headers);

      // Assert
      assertThat(result.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    @DisplayName("should return 400 for pluginShortId with spaces")
    void should_return400_when_pluginShortIdHasSpaces() {
      // Arrange
      WebhookDispatcher dispatcher = createDispatcher(null);
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);

      // Act
      ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai grader", payload, headers);

      // Assert
      assertThat(result.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    @DisplayName("should accept valid pluginShortId with hyphens")
    void should_accept_validPluginShortId() {
      // Arrange
      WebhookDispatcher dispatcher = createDispatcher(null);
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);

      // Act
      ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai-grader-v2", payload, headers);

      // Assert — 202 regardless of dispatch result (async)
      assertThat(result.getStatusCode().value()).isEqualTo(202);
    }
  }

  @Nested
  @DisplayName("Internal secret validation")
  class InternalSecretValidation {

    @Test
    @DisplayName("should return 403 when internal secret is configured but not provided")
    void should_return403_when_secretRequired_butNotProvided() {
      // Arrange
      WebhookDispatcher dispatcher = createDispatcher("my-secret-123");
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);

      // Act
      ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai-grader", payload, headers);

      // Assert
      assertThat(result.getStatusCode().value()).isEqualTo(403);
    }

    @Test
    @DisplayName("should return 403 when internal secret is configured but wrong value provided")
    void should_return403_when_wrongSecretProvided() {
      // Arrange
      WebhookDispatcher dispatcher = createDispatcher("my-secret-123");
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.set(IntegrationHeaders.HEADER_INTERNAL_SECRET, "wrong-secret");

      // Act
      ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai-grader", payload, headers);

      // Assert
      assertThat(result.getStatusCode().value()).isEqualTo(403);
    }

    @Test
    @DisplayName("should return 202 when correct internal secret provided")
    void should_return202_when_correctSecretProvided() {
      // Arrange
      WebhookDispatcher dispatcher = createDispatcher("my-secret-123");
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      headers.set(IntegrationHeaders.HEADER_INTERNAL_SECRET, "my-secret-123");

      // Act
      ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai-grader", payload, headers);

      // Assert
      assertThat(result.getStatusCode().value()).isEqualTo(202);
    }

    @Test
    @DisplayName("should skip secret check when no internal secret configured")
    void should_skip_secretCheck_when_notConfigured() {
      // Arrange — null secret
      WebhookDispatcher dispatcher = createDispatcher(null);
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);

      // Act
      ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai-grader", payload, headers);

      // Assert
      assertThat(result.getStatusCode().value()).isEqualTo(202);
    }

    @Test
    @DisplayName("should skip secret check when internal secret is blank")
    void should_skip_secretCheck_when_blank() {
      // Arrange — blank secret
      WebhookDispatcher dispatcher = createDispatcher("  ");
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);

      // Act
      ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai-grader", payload, headers);

      // Assert
      assertThat(result.getStatusCode().value()).isEqualTo(202);
    }
  }

  @Nested
  @DisplayName("Endpoint resolution")
  class EndpointResolution {

    @Test
    @DisplayName("should use custom host template")
    void should_useCustomHostTemplate() {
      // Arrange
      GatewayProperties properties =
          new GatewayProperties(
              new GatewayProperties.JwtConfig(
                  "http://localhost/certs", "test-issuer", "test-audience", 5),
              Map.of(),
              new GatewayProperties.PermissionsConfig(Map.of()),
              new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
              new GatewayProperties.InstalledCacheConfig(5, 30),
              new GatewayProperties.WebhookConfig(3, 100, 2.0, 9000, "custom-plugin-%s", null),
              new GatewayProperties.Bc02Config("http://localhost:8081"));

      WebhookDispatcher dispatcher =
          new WebhookDispatcher(properties, RestClient.builder(), Runnable::run);

      // Act
      String endpoint = dispatcher.resolvePluginPodEndpoint("quiz");

      // Assert
      assertThat(endpoint).isEqualTo("http://custom-plugin-quiz:9000/webhook");
    }

    @Test
    @DisplayName("should use default host template when not configured")
    void should_useDefaultHostTemplate() {
      // Arrange — null template defaults to "plugin-%s"
      GatewayProperties properties =
          new GatewayProperties(
              new GatewayProperties.JwtConfig(
                  "http://localhost/certs", "test-issuer", "test-audience", 5),
              Map.of(),
              new GatewayProperties.PermissionsConfig(Map.of()),
              new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
              new GatewayProperties.InstalledCacheConfig(5, 30),
              new GatewayProperties.WebhookConfig(3, 100, 2.0, 8080, null, null),
              new GatewayProperties.Bc02Config("http://localhost:8081"));

      WebhookDispatcher dispatcher =
          new WebhookDispatcher(properties, RestClient.builder(), Runnable::run);

      // Act
      String endpoint = dispatcher.resolvePluginPodEndpoint("ai-grader");

      // Assert
      assertThat(endpoint).isEqualTo("http://plugin-ai-grader:8080/webhook");
    }
  }

  private WebhookDispatcher createDispatcher(String internalSecret) {
    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 100, 2.0, 8000, null, internalSecret),
            new GatewayProperties.Bc02Config("http://localhost:8081"));

    return new WebhookDispatcher(properties, RestClient.builder(), Runnable::run);
  }
}
