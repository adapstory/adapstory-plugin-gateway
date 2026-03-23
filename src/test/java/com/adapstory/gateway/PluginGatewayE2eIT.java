package com.adapstory.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.time.Duration;
import java.util.List;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Cross-cutting E2E интеграционные тесты (AC#7). Full flow: JWT auth → Redis permission cache →
 * route proxy → mandatory headers → Kafka invalidation.
 */
class PluginGatewayE2eIT extends AbstractGatewayIntegrationTest {

  private static final String PLUGIN_ID = "adapstory.education_module.ai-grader";
  private static final String TENANT_ID = "tenant-uuid";
  private static final String CACHE_KEY = "plugin:permissions:" + PLUGIN_ID;

  @Autowired private KafkaTemplate<String, String> kafkaTemplate;

  @BeforeEach
  void setupBcMock() {
    BC_WIREMOCK.resetAll();
    BC_WIREMOCK.stubFor(
        get(urlPathEqualTo("/api/content/v1/materials/123"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"id\":\"123\",\"title\":\"E2E Material\"}")));

    // BC-02 permissions stub for intersection model (SEC-3.2)
    stubBc02Permissions(PLUGIN_ID, List.of("content.read"));
  }

  @Test
  @DisplayName(
      "AC#7: Full flow — JWT → Redis cache → proxy → headers → Kafka invalidation → re-cache")
  void fullE2eFlow() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Step 1: First request — JWT auth → permission cached → route proxied
    var response1 =
        testClient
            .get()
            .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);

    assertThat(response1.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response1.getBody()).contains("E2E Material");

    // Verify mandatory headers in response
    assertThat(response1.getHeaders().getFirst("X-Request-Id")).isNotBlank();
    assertThat(response1.getHeaders().getFirst("X-Correlation-Id")).isNotBlank();

    // Verify permissions cached in Redis
    assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNotNull();

    // Verify mandatory headers propagated to BC WireMock
    BC_WIREMOCK.verify(
        getRequestedFor(urlPathEqualTo("/api/content/v1/materials/123"))
            .withHeader("X-Request-Id", matching(".+"))
            .withHeader("X-Correlation-Id", matching(".+"))
            .withHeader("X-User-Id", matching("plugin:" + PLUGIN_ID)));

    // Verify Authorization NOT forwarded
    BC_WIREMOCK.verify(
        getRequestedFor(urlPathEqualTo("/api/content/v1/materials/123"))
            .withoutHeader(HttpHeaders.AUTHORIZATION));

    // Step 2: Publish Kafka invalidation event
    String cloudEvent =
        String.format(
            "{\"specversion\":\"1.0\",\"id\":\"ce-e2e-001\","
                + "\"type\":\"com.adapstory.plugin.domain.event.PluginPermissionsRevoked.v1\","
                + "\"source\":\"/bc02/plugins/%s\","
                + "\"data\":{\"pluginId\":\"%s\","
                + "\"revokedPermissions\":[\"content.write\"],"
                + "\"currentPermissions\":[\"content.read\"]}}",
            PLUGIN_ID, PLUGIN_ID);
    kafkaTemplate.send(
        new ProducerRecord<>("GLOBAL_PLUGIN_PERMISSIONS_REVOKED", PLUGIN_ID, cloudEvent));

    // Step 3: Wait for cache invalidation
    await()
        .atMost(Duration.ofSeconds(10))
        .pollInterval(Duration.ofMillis(200))
        .untilAsserted(() -> assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNull());

    // Step 4: Next request should re-cache permissions
    var response2 =
        testClient
            .get()
            .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);

    assertThat(response2.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNotNull();
  }

  @Test
  @DisplayName("AC#7: Health endpoint — GET /actuator/health → 200 without authentication")
  void healthEndpoint_returns200_withoutAuth() {
    var response = testClient.get().uri("/actuator/health").retrieve().toEntity(String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  @DisplayName("AC#9: Prometheus metrics endpoint — GET /actuator/prometheus → 200 without auth")
  void prometheusEndpoint_returns200_withMetrics() {
    var response = testClient.get().uri("/actuator/prometheus").retrieve().toEntity(String.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).contains("jvm_memory");
  }
}
