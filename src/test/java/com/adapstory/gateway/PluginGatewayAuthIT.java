package com.adapstory.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

/**
 * Интеграционные тесты: JWT Authentication + Permission Enforcement + Route Proxy. Полный Spring
 * контекст с реальными Redis/Kafka (Testcontainers) и WireMock для JWKS + target BC.
 */
class PluginGatewayAuthIT extends AbstractGatewayIntegrationTest {

  private static final String PLUGIN_ID = "adapstory.education_module.ai-grader";
  private static final String TENANT_ID = "tenant-uuid";

  @BeforeEach
  void setupBcMock() {
    BC_WIREMOCK.resetAll();
    BC_WIREMOCK.stubFor(
        get(urlPathEqualTo("/api/content/v1/materials/123"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"id\":\"123\",\"title\":\"Test Material\"}")));

    // BC-02 permissions stub for intersection model (SEC-3.2)
    stubBc02Permissions(PLUGIN_ID, List.of("content.read"));
  }

  @Test
  @DisplayName("AC#1: Valid JWT with content.read → 200 proxied with mandatory headers")
  void validJwt_withPermission_proxiesToBcAndReturnsWithHeaders() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act
    ResponseEntity<String> response =
        testClient
            .get()
            .uri("/gateway/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);

    // Assert
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).contains("Test Material");

    // Mandatory headers in response
    assertThat(response.getHeaders().getFirst("X-Request-Id")).isNotBlank();
    assertThat(response.getHeaders().getFirst("X-Correlation-Id")).isNotBlank();
  }

  @Test
  @DisplayName("AC#2: Valid JWT without required permission → 403 Pattern 8 error")
  void validJwt_withoutPermission_returns403WithPattern8Error() {
    // Arrange — JWT with submission.read, but route requires content.read
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("submission.read"), "CORE");

    // Act & Assert
    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/gateway/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpClientErrorException.class)
        .satisfies(
            ex -> {
              HttpClientErrorException hce = (HttpClientErrorException) ex;
              assertThat(hce.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
              String body = hce.getResponseBodyAsString();
              assertThat(body).contains("pluginId");
              assertThat(body).contains("requiredPermission");
              // grantedPermissions removed per H-2 (information disclosure fix)
            });
  }

  @Test
  @DisplayName("Missing Authorization header → 401")
  void missingAuthHeader_returns401() {
    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/gateway/api/content/v1/materials/123")
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpClientErrorException.class)
        .extracting(ex -> ((HttpClientErrorException) ex).getStatusCode())
        .isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  @DisplayName("Expired JWT → 401")
  void expiredJwt_returns401() {
    String jwt = buildExpiredJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/gateway/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpClientErrorException.class)
        .extracting(ex -> ((HttpClientErrorException) ex).getStatusCode())
        .isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  @DisplayName("Invalid JWT signature → 401")
  void invalidSignatureJwt_returns401() {
    String jwt = buildInvalidSignatureJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/gateway/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpClientErrorException.class)
        .extracting(ex -> ((HttpClientErrorException) ex).getStatusCode())
        .isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  @DisplayName("Authorization header is NOT forwarded to target BC (security)")
  void authorizationHeader_notForwardedToTargetBc() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act
    testClient
        .get()
        .uri("/gateway/api/content/v1/materials/123")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .retrieve()
        .toEntity(String.class);

    // Assert — verify WireMock BC did NOT receive Authorization header
    BC_WIREMOCK.verify(
        getRequestedFor(urlPathEqualTo("/api/content/v1/materials/123"))
            .withoutHeader(HttpHeaders.AUTHORIZATION));
  }

  @Test
  @DisplayName("request-id and correlation-id headers propagated to target BC")
  void mandatoryHeaders_propagatedToTargetBc() {
    // Arrange
    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act
    testClient
        .get()
        .uri("/gateway/api/content/v1/materials/123")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
        .retrieve()
        .toEntity(String.class);

    // Assert — verify WireMock BC received mandatory headers (request-id, correlation-id, user-id)
    BC_WIREMOCK.verify(
        getRequestedFor(urlPathEqualTo("/api/content/v1/materials/123"))
            .withHeader("X-Request-Id", matching(".+"))
            .withHeader("X-Correlation-Id", matching(".+"))
            .withHeader("X-User-Id", equalTo("plugin:" + PLUGIN_ID)));
  }
}
