package com.adapstory.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

/**
 * Интеграционный тест для PluginInstalledCheckFilter (Story FP-0-3, Task 8.4).
 *
 * <p>Проверяет: запрос к установленному плагину → 200; запрос к неустановленному плагину → 404
 * PLUGIN_NOT_INSTALLED; BC-02 недоступен → fail-open. Использует реальные Redis (Testcontainers),
 * WireMock для BC-02.
 */
@DisplayName("Plugin Installed Check Integration (FP-0-3 AC#4)")
class PluginInstalledCheckIT extends AbstractGatewayIntegrationTest {

  private static final String PLUGIN_ID = "adapstory.education.course-catalog";
  private static final String TENANT_ID = "00000000-0000-0000-0000-700000000001";
  private static final String INSTALLED_CHECK_PATH =
      "/api/bc-02/plugin-lifecycle/v1/plugins/" + PLUGIN_ID + "/installed";
  private static final String PERMISSIONS_PATH =
      "/api/bc-02/plugin-lifecycle/v1/plugins/" + PLUGIN_ID + "/permissions";
  private static final String INSTALLED_CACHE_KEY =
      "plugin-gateway:installed:" + PLUGIN_ID + ":" + TENANT_ID;

  @BeforeEach
  void flushInstalledCache() {
    Set<String> keys = redisTemplate.keys("plugin-gateway:installed:*");
    if (keys != null && !keys.isEmpty()) {
      redisTemplate.delete(keys);
    }
  }

  @BeforeEach
  void setupTargetBcMock() {
    BC_WIREMOCK.resetAll();
    BC_WIREMOCK.stubFor(
        get(urlPathMatching("/api/content/v1/.*"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"id\":\"test\"}")));
  }

  @Test
  @DisplayName("should_allow_request_when_plugin_installed_for_tenant")
  void should_allow_request_when_plugin_installed_for_tenant() {
    // Arrange: BC-02 says plugin is installed + has required permissions
    stubBc02Installed(PLUGIN_ID, TENANT_ID, true);
    stubBc02Permissions(PLUGIN_ID, List.of("content.read"));

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
  @DisplayName("should_return_404_when_plugin_not_installed_for_tenant")
  void should_return_404_when_plugin_not_installed_for_tenant() {
    // Arrange: BC-02 says plugin is NOT installed
    stubBc02Installed(PLUGIN_ID, TENANT_ID, false);

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
        .isInstanceOf(HttpClientErrorException.NotFound.class)
        .satisfies(
            ex -> {
              var body = ((HttpClientErrorException.NotFound) ex).getResponseBodyAsString();
              assertThat(body).contains("PLUGIN_NOT_INSTALLED");
              assertThat(body).contains(PLUGIN_ID);
              assertThat(body).contains(TENANT_ID);
            });
  }

  @Test
  @DisplayName("should_allow_request_failopen_when_bc02_unavailable")
  void should_allow_request_failopen_when_bc02_unavailable() {
    // Arrange: BC-02 installed endpoint returns 500 (unavailable)
    // BUT permissions endpoint returns valid permissions (to let PermissionEnforcementFilter pass)
    BC02_WIREMOCK.stubFor(
        get(urlPathEqualTo(INSTALLED_CHECK_PATH)).willReturn(aResponse().withStatus(500)));
    stubBc02Permissions(PLUGIN_ID, List.of("content.read"));

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act — fail-open: request should pass through
    var response =
        testClient
            .get()
            .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);

    // Assert — request allowed (fail-open with warning log)
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  @DisplayName("should_cache_installed_status_in_redis_after_first_request")
  void should_cache_installed_status_in_redis_after_first_request() {
    // Arrange
    stubBc02Installed(PLUGIN_ID, TENANT_ID, true);
    stubBc02Permissions(PLUGIN_ID, List.of("content.read"));

    assertThat(redisTemplate.opsForValue().get(INSTALLED_CACHE_KEY)).isNull();

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act
    testClient
        .get()
        .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .retrieve()
        .toEntity(String.class);

    // Assert — installed status cached in Redis
    String cached = redisTemplate.opsForValue().get(INSTALLED_CACHE_KEY);
    assertThat(cached).isEqualTo("true");
  }

  @Test
  @DisplayName("should_not_call_bc02_on_cache_hit")
  void should_not_call_bc02_on_cache_hit() {
    // Arrange
    stubBc02Installed(PLUGIN_ID, TENANT_ID, true);
    stubBc02Permissions(PLUGIN_ID, List.of("content.read"));

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act — first request (cache miss → BC-02 fetch)
    testClient
        .get()
        .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .retrieve()
        .toEntity(String.class);

    BC02_WIREMOCK.verify(1, getRequestedFor(urlPathEqualTo(INSTALLED_CHECK_PATH)));

    // Act — second request (cache hit → no BC-02 call)
    testClient
        .get()
        .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .retrieve()
        .toEntity(String.class);

    // Assert — BC-02 installed check still called only once
    BC02_WIREMOCK.verify(1, getRequestedFor(urlPathEqualTo(INSTALLED_CHECK_PATH)));
  }

  @Test
  @DisplayName("should_have_ttl_on_installed_cache_entry")
  void should_have_ttl_on_installed_cache_entry() {
    // Arrange
    stubBc02Installed(PLUGIN_ID, TENANT_ID, true);
    stubBc02Permissions(PLUGIN_ID, List.of("content.read"));

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act
    testClient
        .get()
        .uri("/api/bc-02/gateway/v1/api/content/v1/materials/123")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .retrieve()
        .toEntity(String.class);

    // Assert — TTL is set on cache key
    Long ttl = redisTemplate.getExpire(INSTALLED_CACHE_KEY, TimeUnit.SECONDS);
    assertThat(ttl).isNotNull().isGreaterThan(0).isLessThanOrEqualTo(300);
  }

  @Test
  @DisplayName("should_include_plugin_id_and_tenant_id_in_404_response")
  void should_include_plugin_id_and_tenant_id_in_404_response() {
    // Arrange
    stubBc02Installed(PLUGIN_ID, TENANT_ID, false);

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
        .isInstanceOf(HttpClientErrorException.NotFound.class)
        .satisfies(
            ex -> {
              var body = ((HttpClientErrorException.NotFound) ex).getResponseBodyAsString();
              assertThat(body).contains("plugin_id");
              assertThat(body).contains("tenant_id");
              assertThat(body).contains("error_code");
              assertThat(body).contains("PLUGIN_NOT_INSTALLED");
            });
  }

  // ---------------------------------------------------------------------------
  // WireMock helpers
  // ---------------------------------------------------------------------------

  private static void stubBc02Installed(String pluginId, String tenantId, boolean installed) {
    String body =
        String.format(
            "{\"data\":{\"installed\":%s,\"version\":%s},\"messages\":[],\"error\":null}",
            installed, installed ? "\"1.0.0\"" : "null");

    BC02_WIREMOCK.stubFor(
        get(urlPathEqualTo("/api/bc-02/plugin-lifecycle/v1/plugins/" + pluginId + "/installed"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(body)));
  }
}
