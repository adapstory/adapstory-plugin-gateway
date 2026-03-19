package com.adapstory.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * Интеграционные тесты: Redis Permission Cache + Kafka Invalidation (AC#5, AC#6). Реальные Redis
 * (Testcontainers) и Kafka.
 */
class PermissionCacheIT extends AbstractGatewayIntegrationTest {

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
                    .withBody("{\"id\":\"123\"}")));
  }

  @Test
  @DisplayName("AC#5: First request → cache miss → cached in Redis → second request → cache hit")
  void permissionsCachedInRedis_andHitOnSecondRequest() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Assert: cache is empty
    assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNull();

    // Act: first request (cache miss → cache set)
    var response1 =
        testClient
            .get()
            .uri("/gateway/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);
    assertThat(response1.getStatusCode()).isEqualTo(HttpStatus.OK);

    // Assert: permissions cached in Redis
    String cached = redisTemplate.opsForValue().get(CACHE_KEY);
    assertThat(cached).isNotNull();
    assertThat(cached).contains("content.read");

    // Act: second request (cache hit)
    var response2 =
        testClient
            .get()
            .uri("/gateway/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);
    assertThat(response2.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  @DisplayName("AC#6: PluginPermissionsChanged Kafka event → consumer invalidates Redis cache key")
  void kafkaEvent_invalidatesRedisCache() {
    // Arrange: pre-populate cache
    redisTemplate
        .opsForValue()
        .set(CACHE_KEY, "content.read,submission.read", Duration.ofMinutes(5));
    assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNotNull();

    // Act: publish PluginPermissionsChanged CloudEvents event
    String cloudEvent =
        String.format(
            """
            {"specversion":"1.0","type":"PluginPermissionsChanged","source":"bc02",\
            "data":{"pluginId":"%s","tenantId":"%s"}}""",
            PLUGIN_ID, TENANT_ID);

    kafkaTemplate.send(new ProducerRecord<>("plugin.permissions.changed", PLUGIN_ID, cloudEvent));

    // Assert: wait for consumer to process and invalidate
    await()
        .atMost(Duration.ofSeconds(10))
        .pollInterval(Duration.ofMillis(200))
        .untilAsserted(() -> assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNull());
  }

  @Test
  @DisplayName("AC#5: TTL is set correctly on cached permissions")
  void permissionCache_hasTtl() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act: trigger cache set
    testClient
        .get()
        .uri("/gateway/api/content/v1/materials/123")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .retrieve()
        .toEntity(String.class);

    // Assert: TTL is set on the key
    Long ttl = redisTemplate.getExpire(CACHE_KEY, TimeUnit.SECONDS);
    assertThat(ttl).isNotNull();
    assertThat(ttl).isGreaterThan(0);
    assertThat(ttl).isLessThanOrEqualTo(300); // 5 minutes = 300 seconds
  }
}
