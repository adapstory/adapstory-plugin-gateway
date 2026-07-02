package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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

    @ParameterizedTest
    @CsvSource({"'../../etc/passwd',400", "'ai grader',400", "'ai-grader-v2',202"})
    @DisplayName("should validate pluginShortId before dispatch")
    void should_validatePluginShortId_when_dispatching(String pluginShortId, int expectedStatus) {
      WebhookDispatcher dispatcher = createDispatcher(null);
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);

      ResponseEntity<Void> result = dispatcher.dispatchWebhook(pluginShortId, payload, headers);

      assertThat(result.getStatusCode().value()).isEqualTo(expectedStatus);
    }
  }

  @Nested
  @DisplayName("Internal secret validation")
  class InternalSecretValidation {

    @ParameterizedTest
    @CsvSource({
      "'my-secret-123',,403",
      "'my-secret-123','wrong-secret',403",
      "'my-secret-123','my-secret-123',202",
      ",,202",
      "'  ',,202"
    })
    @DisplayName("should enforce internal secret only when configured")
    void should_enforceInternalSecret_when_dispatching(
        String configuredSecret, String providedSecret, int expectedStatus) {
      WebhookDispatcher dispatcher = createDispatcher(configuredSecret);
      byte[] payload = "{}".getBytes();
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      if (providedSecret != null && !providedSecret.isBlank()) {
        headers.set(IntegrationHeaders.HEADER_INTERNAL_SECRET, providedSecret);
      }

      ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai-grader", payload, headers);

      assertThat(result.getStatusCode().value()).isEqualTo(expectedStatus);
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
              Map.of(),
              new GatewayProperties.PermissionsConfig(Map.of()),
              new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
              new GatewayProperties.InstalledCacheConfig(5, 30),
              new GatewayProperties.WebhookConfig(3, 100, 2.0, 9000, "custom-plugin-%s", null),
              new GatewayProperties.Bc02Config("http://localhost:8081"),
              null);

      WebhookDispatchService dispatchService =
          new WebhookDispatchService(
              properties,
              new RestClientWebhookDeliveryAdapter(RestClient.builder()),
              Runnable::run);
      WebhookDispatcher dispatcher = new WebhookDispatcher(properties, dispatchService);

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
              Map.of(),
              new GatewayProperties.PermissionsConfig(Map.of()),
              new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
              new GatewayProperties.InstalledCacheConfig(5, 30),
              new GatewayProperties.WebhookConfig(3, 100, 2.0, 8080, null, null),
              new GatewayProperties.Bc02Config("http://localhost:8081"),
              null);

      WebhookDispatchService dispatchService =
          new WebhookDispatchService(
              properties,
              new RestClientWebhookDeliveryAdapter(RestClient.builder()),
              Runnable::run);
      WebhookDispatcher dispatcher = new WebhookDispatcher(properties, dispatchService);

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
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 100, 2.0, 8000, null, internalSecret),
            new GatewayProperties.Bc02Config("http://localhost:8081"),
            null);

    WebhookDispatchService dispatchService =
        new WebhookDispatchService(
            properties, new RestClientWebhookDeliveryAdapter(RestClient.builder()), Runnable::run);
    return new WebhookDispatcher(properties, dispatchService);
  }
}
