package com.adapstory.gateway.routing;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.config.GatewayProperties;
import com.github.tomakehurst.wiremock.WireMockServer;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;
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
@Isolated
class WebhookDispatcherTest {

  private static final String COMMAND_KEY = "550e8400-e29b-41d4-a716-446655440000";

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
            properties,
            new RestClientWebhookDeliveryAdapter(RestClient.builder()),
            Runnable::run,
            testStore());
    dispatcher = new WebhookDispatcher(properties, dispatchService);
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Test
  @DisplayName("Dispatch returns 202 Accepted immediately (async)")
  void shouldReturn202WhenDispatchWebhook() {
    // Arrange
    wireMockServer.stubFor(post("/webhook").willReturn(aResponse().withStatus(200)));

    byte[] payload = "{\"type\":\"test.event\",\"data\":{}}".getBytes();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set("X-Idempotency-Key", COMMAND_KEY);

    // Act
    ResponseEntity<Void> result =
        dispatcher.dispatchWebhook("ai-grader", payload, COMMAND_KEY, headers);

    // Assert — immediate 202, dispatch happens async
    assertThat(result.getStatusCode().value()).isEqualTo(202);
  }

  @Test
  @DisplayName("Missing, duplicated, and invalid command keys are rejected before dispatch")
  void shouldRejectInvalidCommandKeysBeforeDispatch() {
    byte[] payload = "{}".getBytes();
    HttpHeaders headers = new HttpHeaders();

    assertThat(
            dispatcher.dispatchWebhook("ai-grader", payload, null, headers).getStatusCode().value())
        .isEqualTo(400);

    headers.add("X-Idempotency-Key", COMMAND_KEY);
    headers.add("X-Idempotency-Key", COMMAND_KEY);
    assertThat(
            dispatcher
                .dispatchWebhook("ai-grader", payload, COMMAND_KEY, headers)
                .getStatusCode()
                .value())
        .isEqualTo(400);

    headers.set("X-Idempotency-Key", "invalid key");
    assertThat(
            dispatcher
                .dispatchWebhook("ai-grader", payload, "invalid key", headers)
                .getStatusCode()
                .value())
        .isEqualTo(400);
    wireMockServer.verify(0, postRequestedFor(urlEqualTo("/webhook")));
  }

  @ParameterizedTest(name = "status {0} -> {1} attempts")
  @CsvSource({
    "200, 1", "400, 1", "500, 3",
  })
  @DisplayName("Retry policy follows HTTP status contract")
  void shouldApplyRetryPolicyWhenExecuteWithRetry(int statusCode, int expectedAttempts) {
    // Arrange
    wireMockServer.stubFor(post("/webhook").willReturn(aResponse().withStatus(statusCode)));

    byte[] payload = "{\"type\":\"test.event\"}".getBytes();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set("X-Idempotency-Key", COMMAND_KEY);

    // Act
    dispatchService.executeWithRetry("ai-grader", webhookUrl(), payload, headers);

    // Assert
    wireMockServer.verify(expectedAttempts, postRequestedFor(urlEqualTo("/webhook")));
    wireMockServer.verify(
        expectedAttempts,
        postRequestedFor(urlEqualTo("/webhook"))
            .withHeader("X-Idempotency-Key", equalTo(COMMAND_KEY)));
  }

  @Test
  @DisplayName("Retry on 5xx — succeeds on final configured attempt")
  void shouldRetryOn5xxUntilSuccessWhenExecuteWithRetry() {
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
  void shouldPluginPodEndpointResolutionWhenInvoked() {
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
            properties,
            new RestClientWebhookDeliveryAdapter(RestClient.builder()),
            Runnable::run,
            testStore());
    WebhookDispatcher realDispatcher = new WebhookDispatcher(properties, realDispatchService);

    assertThat(realDispatcher.resolvePluginPodEndpoint("ai-grader"))
        .isEqualTo("http://plugin-ai-grader:8000/webhook");
  }

  private String webhookUrl() {
    return "http://127.0.0.1:" + wireMockServer.port() + "/webhook";
  }

  private static WebhookDispatchStore testStore() {
    WebhookDispatchStore store = mock(WebhookDispatchStore.class);
    when(store.admit(any())).thenReturn(WebhookDispatchStore.Admission.NEW);
    when(store.claim(anyString())).thenReturn(Optional.empty());
    return store;
  }
}
