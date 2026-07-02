package com.adapstory.gateway.routing;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.gateway.config.GatewayProperties;
import com.github.tomakehurst.wiremock.WireMockServer;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

/**
 * Тесты WebhookDispatcher: async dispatch (202), retry on 5xx, no retry on 4xx, endpoint
 * resolution.
 */
class WebhookDispatcherTest {

  private WireMockServer wireMockServer;
  private WebhookDispatchService dispatchService;
  private WebhookDispatcher dispatcher;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(0);
    wireMockServer.start();

    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 100, 2.0, wireMockServer.port(), null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"),
            null);

    dispatchService =
        new WebhookDispatchService(
            properties, new RestClientWebhookDeliveryAdapter(RestClient.builder()), Runnable::run);
    dispatcher = new WebhookDispatcher(properties, dispatchService);
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Test
  @DisplayName("Dispatch returns 202 Accepted immediately (async)")
  void should_return202_when_dispatchWebhook() {
    // Arrange
    wireMockServer.stubFor(post("/webhook").willReturn(aResponse().withStatus(200)));

    byte[] payload = "{\"type\":\"test.event\",\"data\":{}}".getBytes();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    // Act
    ResponseEntity<Void> result = dispatcher.dispatchWebhook("ai-grader", payload, headers);

    // Assert — immediate 202, dispatch happens async
    assertThat(result.getStatusCode().value()).isEqualTo(202);
  }

  @ParameterizedTest(name = "status {0} -> {1} attempts")
  @CsvSource({
    "200, 1", "400, 1", "500, 3",
  })
  @DisplayName("Retry policy follows HTTP status contract")
  void should_apply_retry_policy_when_executeWithRetry(int statusCode, int expectedAttempts) {
    // Arrange
    wireMockServer.stubFor(post("/webhook").willReturn(aResponse().withStatus(statusCode)));

    byte[] payload = "{\"type\":\"test.event\"}".getBytes();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    // Act
    dispatchService.executeWithRetry("ai-grader", webhookUrl(), payload, headers);

    // Assert
    wireMockServer.verify(expectedAttempts, postRequestedFor(urlEqualTo("/webhook")));
  }

  @Test
  @DisplayName("Retry on 5xx — succeeds on final configured attempt")
  void should_retryOn5xx_until_success_when_executeWithRetry() {
    // Arrange — first 2 calls fail with 500, 3rd succeeds
    wireMockServer.stubFor(
        post("/webhook")
            .inScenario("retry")
            .whenScenarioStateIs("Started")
            .willReturn(aResponse().withStatus(500))
            .willSetStateTo("attempt-2"));

    wireMockServer.stubFor(
        post("/webhook")
            .inScenario("retry")
            .whenScenarioStateIs("attempt-2")
            .willReturn(aResponse().withStatus(500))
            .willSetStateTo("attempt-3"));

    wireMockServer.stubFor(
        post("/webhook")
            .inScenario("retry")
            .whenScenarioStateIs("attempt-3")
            .willReturn(aResponse().withStatus(200)));

    byte[] payload = "{\"type\":\"test.event\"}".getBytes();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    // Act
    dispatchService.executeWithRetry("ai-grader", webhookUrl(), payload, headers);

    // Assert — should succeed on 3rd attempt
    wireMockServer.verify(3, postRequestedFor(urlEqualTo("/webhook")));
  }

  @Test
  @DisplayName("Plugin pod endpoint resolution follows naming convention")
  void should_plugin_pod_endpoint_resolution_when_invoked() {
    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.InstalledCacheConfig(5, 30),
            new GatewayProperties.WebhookConfig(3, 100, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"),
            null);

    WebhookDispatchService realDispatchService =
        new WebhookDispatchService(
            properties, new RestClientWebhookDeliveryAdapter(RestClient.builder()), Runnable::run);
    WebhookDispatcher realDispatcher = new WebhookDispatcher(properties, realDispatchService);

    assertThat(realDispatcher.resolvePluginPodEndpoint("ai-grader"))
        .isEqualTo("http://plugin-ai-grader:8000/webhook");
  }

  private String webhookUrl() {
    return "http://127.0.0.1:" + wireMockServer.port() + "/webhook";
  }
}
