package com.adapstory.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.github.tomakehurst.wiremock.WireMockServer;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Интеграционные тесты: Webhook Dispatch (AC#4). WireMock для plugin pod. */
class WebhookDispatchIT extends AbstractGatewayIntegrationTest {

  static final WireMockServer PLUGIN_POD_WIREMOCK = new WireMockServer(0);

  static {
    PLUGIN_POD_WIREMOCK.start();
  }

  @DynamicPropertySource
  static void configureWebhookPort(DynamicPropertyRegistry registry) {
    registry.add("gateway.webhook.plugin-pod-port", PLUGIN_POD_WIREMOCK::port);
    registry.add("gateway.webhook.plugin-pod-host-template", () -> "localhost");
  }

  @BeforeEach
  void resetPluginPod() {
    PLUGIN_POD_WIREMOCK.resetAll();
  }

  @Test
  @DisplayName("AC#4: POST /internal/webhooks/{pluginShortId} → 202 → plugin pod receives payload")
  void webhookDispatch_forwardsToPluginPod() {
    // Arrange: WireMock plugin pod accepts webhook
    PLUGIN_POD_WIREMOCK.stubFor(
        post(urlPathEqualTo("/webhook")).willReturn(aResponse().withStatus(200)));

    String cloudEventsPayload =
        """
        {"specversion":"1.0","type":"content.updated","source":"core","data":{"materialId":"123"}}
        """;

    // Act
    ResponseEntity<Void> response =
        testClient
            .post()
            .uri("/internal/webhooks/ai-grader")
            .header("X-Correlation-Id", "test-corr-123")
            .contentType(MediaType.APPLICATION_JSON)
            .body(cloudEventsPayload.getBytes())
            .retrieve()
            .toBodilessEntity();

    // Assert
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);

    // Wait for async dispatch to complete and verify CloudEvents payload
    await()
        .atMost(Duration.ofSeconds(5))
        .untilAsserted(
            () -> {
              PLUGIN_POD_WIREMOCK.verify(
                  postRequestedFor(urlPathEqualTo("/webhook"))
                      .withHeader("X-Correlation-Id", equalTo("test-corr-123"))
                      .withHeader("Content-Type", equalTo("application/json")));

              // Verify CloudEvents body payload integrity
              var requests =
                  PLUGIN_POD_WIREMOCK.findAll(postRequestedFor(urlPathEqualTo("/webhook")));
              assertThat(requests).isNotEmpty();
              String receivedBody = requests.get(0).getBodyAsString();
              assertThat(receivedBody).contains("\"specversion\":\"1.0\"");
              assertThat(receivedBody).contains("\"type\":\"content.updated\"");
              assertThat(receivedBody).contains("\"source\":\"core\"");
              assertThat(receivedBody).contains("\"materialId\":\"123\"");
            });
  }

  @Test
  @DisplayName("Webhook dispatch to unavailable pod → retries")
  void webhookDispatch_retriesOnFailure() {
    // Arrange: WireMock returns 500 (will be retried)
    PLUGIN_POD_WIREMOCK.stubFor(
        post(urlPathEqualTo("/webhook")).willReturn(aResponse().withStatus(500)));

    String payload = "{\"specversion\":\"1.0\",\"type\":\"test\",\"source\":\"core\",\"data\":{}}";

    // Act
    ResponseEntity<Void> response =
        testClient
            .post()
            .uri("/internal/webhooks/ai-grader")
            .contentType(MediaType.APPLICATION_JSON)
            .body(payload.getBytes())
            .retrieve()
            .toBodilessEntity();

    // Assert: 202 returned immediately
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);

    // Wait for retries to complete (retry-max-attempts=2 in test profile)
    await()
        .atMost(Duration.ofSeconds(10))
        .untilAsserted(
            () -> {
              int requestCount =
                  PLUGIN_POD_WIREMOCK
                      .countRequestsMatching(postRequestedFor(urlPathEqualTo("/webhook")).build())
                      .getCount();
              assertThat(requestCount).isEqualTo(2);
            });
  }
}
