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
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.WebhookConfig(3, 100, 2.0, wireMockServer.port(), null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"));

    dispatcher =
        new WebhookDispatcher(properties, RestClient.builder(), Runnable::run) {
          @Override
          String resolvePluginPodEndpoint(String pluginShortId) {
            return wireMockServer.baseUrl() + "/webhook";
          }
        };
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Test
  @DisplayName("Dispatch returns 202 Accepted immediately (async)")
  void dispatchWebhook_returns202() {
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

  @Test
  @DisplayName("Successful dispatch on first attempt")
  void executeWithRetry_successOnFirstAttempt() {
    // Arrange
    wireMockServer.stubFor(post("/webhook").willReturn(aResponse().withStatus(200)));

    byte[] payload = "{\"type\":\"test.event\",\"data\":{}}".getBytes();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    // Act — call executeWithRetry directly (synchronous)
    dispatcher.executeWithRetry(
        "ai-grader", wireMockServer.baseUrl() + "/webhook", payload, headers);

    // Assert
    wireMockServer.verify(1, postRequestedFor(urlEqualTo("/webhook")));
  }

  @Test
  @DisplayName("Retry on 5xx — retries configured number of times")
  void executeWithRetry_retriesOn5xx() {
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
    dispatcher.executeWithRetry(
        "ai-grader", wireMockServer.baseUrl() + "/webhook", payload, headers);

    // Assert — should succeed on 3rd attempt
    wireMockServer.verify(3, postRequestedFor(urlEqualTo("/webhook")));
  }

  @Test
  @DisplayName("4xx client error — does NOT retry (H4 fix)")
  void executeWithRetry_doesNotRetryOn4xx() {
    // Arrange — plugin pod returns 400 Bad Request
    wireMockServer.stubFor(post("/webhook").willReturn(aResponse().withStatus(400)));

    byte[] payload = "{\"type\":\"test.event\"}".getBytes();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    // Act
    dispatcher.executeWithRetry(
        "ai-grader", wireMockServer.baseUrl() + "/webhook", payload, headers);

    // Assert — only 1 attempt, no retry for 4xx
    wireMockServer.verify(1, postRequestedFor(urlEqualTo("/webhook")));
  }

  @Test
  @DisplayName("All retries exhausted on 5xx — logs error")
  void executeWithRetry_allRetriesExhausted() {
    // Arrange — all calls fail with 500
    wireMockServer.stubFor(post("/webhook").willReturn(aResponse().withStatus(500)));

    byte[] payload = "{\"type\":\"test.event\"}".getBytes();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    // Act
    dispatcher.executeWithRetry(
        "ai-grader", wireMockServer.baseUrl() + "/webhook", payload, headers);

    // Assert — 3 attempts (configured max)
    wireMockServer.verify(3, postRequestedFor(urlEqualTo("/webhook")));
  }

  @Test
  @DisplayName("Plugin pod endpoint resolution follows naming convention")
  void pluginPodEndpointResolution() {
    // Need a fresh instance without the override
    GatewayProperties properties =
        new GatewayProperties(
            new GatewayProperties.JwtConfig(
                "http://localhost/certs", "test-issuer", "test-audience", 5),
            Map.of(),
            new GatewayProperties.PermissionsConfig(Map.of()),
            new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
            new GatewayProperties.WebhookConfig(3, 100, 2.0, 8000, null, null),
            new GatewayProperties.Bc02Config("http://localhost:8081"));

    WebhookDispatcher realDispatcher =
        new WebhookDispatcher(properties, RestClient.builder(), Runnable::run);

    assertThat(realDispatcher.resolvePluginPodEndpoint("ai-grader"))
        .isEqualTo("http://plugin-ai-grader:8000/webhook");
  }
}
