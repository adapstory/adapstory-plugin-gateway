package com.adapstory.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

/**
 * Интеграционные тесты: Redis Permission Cache + Kafka Invalidation + BC-02 REST fallback
 * (SEC-3.2). Реальные Redis (Testcontainers), Kafka и WireMock BC-02.
 */
class PermissionCacheIT extends AbstractGatewayIntegrationTest {

  private static final String PLUGIN_ID = "adapstory.education_module.ai-grader";
  private static final String TENANT_ID = "tenant-uuid";
  private static final String CACHE_KEY = "plugin:permissions:" + PLUGIN_ID;
  private static final String BC02_PERMISSIONS_PATH =
      "/api/bc-02/plugin-lifecycle/v1/plugins/" + PLUGIN_ID + "/permissions";

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

    // Default: BC-02 returns content.read for this plugin
    stubBc02Permissions(PLUGIN_ID, List.of("content.read"));
  }

  @Test
  @DisplayName(
      "AC#3: Cache miss → BC-02 fetch → cached in Redis → second request → cache hit (no BC-02 call)")
  void cacheMiss_fetchFromBc02_thenCacheHit() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");
    assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNull();

    // Act: first request (cache miss → BC-02 fetch → cache set)
    var response1 =
        testClient
            .get()
            .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);
    assertThat(response1.getStatusCode()).isEqualTo(HttpStatus.OK);

    // Assert: permissions cached in Redis (from BC-02, not JWT)
    String cached = redisTemplate.opsForValue().get(CACHE_KEY);
    assertThat(cached).isNotNull().contains("content.read");

    // Assert: BC-02 was called exactly once
    BC02_WIREMOCK.verify(1, getRequestedFor(urlPathEqualTo(BC02_PERMISSIONS_PATH)));

    // Act: second request (cache hit → no BC-02 call)
    var response2 =
        testClient
            .get()
            .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);
    assertThat(response2.getStatusCode()).isEqualTo(HttpStatus.OK);

    // Assert: BC-02 still called only once (cache hit on second request)
    BC02_WIREMOCK.verify(1, getRequestedFor(urlPathEqualTo(BC02_PERMISSIONS_PATH)));
  }

  @Test
  @DisplayName("AC#1: Permission in JWT but NOT in BC-02 manifest → 403 ADAP-SEC-0010")
  void permissionRevokedInManifest_returns403() {
    // Arrange: BC-02 returns only submission.read (content.read revoked)
    BC02_WIREMOCK.resetMappings();
    stubBc02Permissions(PLUGIN_ID, List.of("submission.read"));

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act & Assert
    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .satisfies(
            ex -> {
              var body = ((HttpClientErrorException.Forbidden) ex).getResponseBodyAsString();
              assertThat(body).contains("ADAP-SEC-0010");
              assertThat(body).contains("has been revoked");
            });
  }

  @Test
  @DisplayName("AC#2: Permission in both JWT AND manifest → request allowed")
  void permissionInBothJwtAndManifest_requestAllowed() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act
    var response =
        testClient
            .get()
            .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);

    // Assert
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  @DisplayName("AC#4: Redis miss AND BC-02 unavailable → 503 ADAP-SEC-0011 (fail-closed)")
  void redisMissAndBc02Unavailable_returns503() {
    // Arrange: BC-02 returns 500
    BC02_WIREMOCK.resetMappings();
    BC02_WIREMOCK.stubFor(
        get(urlPathEqualTo(BC02_PERMISSIONS_PATH)).willReturn(aResponse().withStatus(500)));

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act & Assert
    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpServerErrorException.ServiceUnavailable.class)
        .satisfies(
            ex -> {
              var body =
                  ((HttpServerErrorException.ServiceUnavailable) ex).getResponseBodyAsString();
              assertThat(body).contains("ADAP-SEC-0011");
              assertThat(body).contains("Unable to verify plugin permissions");
            });
  }

  @Nested
  @DisplayName("SEC-3.1: PluginPermissionsRevoked Kafka event handling")
  class RevocationEventHandling {

    @Test
    @DisplayName(
        "AC#5: Revocation event → cache invalidated → next request fetches from BC-02 (not JWT)")
    void revocationEvent_invalidatesCache_nextRequestFetchesFromBc02() {
      // Arrange: pre-populate cache with old permissions
      redisTemplate
          .opsForValue()
          .set(CACHE_KEY, "content.read,submission.read", Duration.ofMinutes(5));

      // Act: publish PluginPermissionsRevoked CloudEvents event
      String cloudEvent =
          String.format(
              """
              {"specversion":"1.0","id":"ce-it-sec32-001",\
              "type":"com.adapstory.plugin.domain.event.PluginPermissionsRevoked.v1",\
              "source":"/bc02/plugins/%s",\
              "data":{"pluginId":"%s",\
              "revokedPermissions":["submission.read"],\
              "currentPermissions":["content.read"]}}""",
              PLUGIN_ID, PLUGIN_ID);

      kafkaTemplate.send(
          new ProducerRecord<>("GLOBAL_PLUGIN_PERMISSIONS_REVOKED", PLUGIN_ID, cloudEvent));

      // Assert: cache invalidated
      org.awaitility.Awaitility.await()
          .atMost(Duration.ofSeconds(10))
          .pollInterval(Duration.ofMillis(200))
          .untilAsserted(() -> assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNull());

      // Act: next request → cache miss → BC-02 fetch (not JWT fallback)
      // BC-02 returns only content.read (submission.read revoked)
      BC02_WIREMOCK.resetMappings();
      stubBc02Permissions(PLUGIN_ID, List.of("content.read"));

      String jwt =
          buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read", "submission.read"), "CORE");

      var response =
          testClient
              .get()
              .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
              .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
              .retrieve()
              .toEntity(String.class);
      assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

      // Assert: new cache entry is from BC-02 (content.read only)
      String cached = redisTemplate.opsForValue().get(CACHE_KEY);
      assertThat(cached).isEqualTo("content.read");
    }

    @Test
    @DisplayName("AC#2: GLOBAL_PLUGIN_PERMISSIONS_REVOKED event invalidates Redis cache")
    void revocationEvent_invalidatesRedisCache() {
      // Arrange: pre-populate cache
      redisTemplate
          .opsForValue()
          .set(CACHE_KEY, "content.read,submission.read", Duration.ofMinutes(5));
      assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNotNull();

      // Act: publish PluginPermissionsRevoked CloudEvents event
      String cloudEvent =
          String.format(
              """
              {"specversion":"1.0","id":"ce-it-sec32-002",\
              "type":"com.adapstory.plugin.domain.event.PluginPermissionsRevoked.v1",\
              "source":"/bc02/plugins/%s",\
              "data":{"pluginId":"%s",\
              "revokedPermissions":["content.write"],\
              "currentPermissions":["content.read"]}}""",
              PLUGIN_ID, PLUGIN_ID);

      kafkaTemplate.send(
          new ProducerRecord<>("GLOBAL_PLUGIN_PERMISSIONS_REVOKED", PLUGIN_ID, cloudEvent));

      // Assert: wait for consumer to process and invalidate
      org.awaitility.Awaitility.await()
          .atMost(Duration.ofSeconds(10))
          .pollInterval(Duration.ofMillis(200))
          .untilAsserted(() -> assertThat(redisTemplate.opsForValue().get(CACHE_KEY)).isNull());
    }
  }

  @Test
  @DisplayName("AC#5: TTL is set correctly on cached permissions")
  void permissionCache_hasTtl() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act: trigger cache set via BC-02 fetch
    testClient
        .get()
        .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .retrieve()
        .toEntity(String.class);

    // Assert: TTL is set on the key
    Long ttl = redisTemplate.getExpire(CACHE_KEY, TimeUnit.SECONDS);
    assertThat(ttl).isNotNull();
    assertThat(ttl).isGreaterThan(0);
    assertThat(ttl).isLessThanOrEqualTo(300); // 5 minutes = 300 seconds
  }

  @Test
  @DisplayName("AC#7: Empty manifest permissions → 403 for any permission")
  void emptyManifestPermissions_returns403() {
    // Arrange: BC-02 returns empty permissions
    BC02_WIREMOCK.resetMappings();
    stubBc02Permissions(PLUGIN_ID, List.of());

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act & Assert
    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpClientErrorException.Forbidden.class)
        .satisfies(
            ex -> {
              var body = ((HttpClientErrorException.Forbidden) ex).getResponseBodyAsString();
              assertThat(body).contains("ADAP-SEC-0010");
            });
  }

  @Test
  @DisplayName("L-2: Negative cache sentinel prevents repeated BC-02 calls (thundering herd)")
  void negativeCacheSentinel_preventsBc02Calls() {
    // Arrange: BC-02 returns 500 (first request stores negative sentinel)
    BC02_WIREMOCK.resetMappings();
    BC02_WIREMOCK.stubFor(
        get(urlPathEqualTo(BC02_PERMISSIONS_PATH)).willReturn(aResponse().withStatus(500)));

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act 1: first request → cache miss → BC-02 fails → negative sentinel stored → 503
    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpServerErrorException.ServiceUnavailable.class);

    // Assert: negative sentinel in Redis
    String cached = redisTemplate.opsForValue().get(CACHE_KEY);
    assertThat(cached).isEqualTo("__UNAVAILABLE__");

    // Act 2: second request → negative sentinel active → no BC-02 call → 503
    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpServerErrorException.ServiceUnavailable.class);

    // Assert: BC-02 called only once (negative cache prevented second call)
    BC02_WIREMOCK.verify(1, getRequestedFor(urlPathEqualTo(BC02_PERMISSIONS_PATH)));
  }
}
