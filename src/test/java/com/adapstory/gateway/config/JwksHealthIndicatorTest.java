package com.adapstory.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.web.client.RestClient;

/**
 * Тесты JwksHealthIndicator: проверка доступности Keycloak JWKS endpoint.
 *
 * <p>Покрывает: healthy (UP), unhealthy (DOWN), connection error.
 */
@DisplayName("JwksHealthIndicator")
class JwksHealthIndicatorTest {

  private WireMockServer wireMockServer;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(0);
    wireMockServer.start();
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Test
  @DisplayName("should return UP when JWKS endpoint is reachable")
  void should_returnUp_when_jwksReachable() {
    // Arrange
    wireMockServer.stubFor(WireMock.get("/certs").willReturn(WireMock.okJson("{\"keys\":[]}")));

    GatewayProperties properties = buildProperties(wireMockServer.baseUrl() + "/certs");
    JwksHealthIndicator indicator = new JwksHealthIndicator(properties, RestClient.builder());

    // Act
    Health health = indicator.health();

    // Assert
    assertThat(health.getStatus()).isEqualTo(Status.UP);
    assertThat(health.getDetails().get("jwksUri")).isEqualTo(wireMockServer.baseUrl() + "/certs");
  }

  @Test
  @DisplayName("should return DOWN when JWKS endpoint returns server error")
  void should_returnDown_when_jwksServerError() {
    // Arrange
    wireMockServer.stubFor(
        WireMock.get("/certs").willReturn(WireMock.serverError().withBody("Internal Error")));

    GatewayProperties properties = buildProperties(wireMockServer.baseUrl() + "/certs");
    JwksHealthIndicator indicator = new JwksHealthIndicator(properties, RestClient.builder());

    // Act
    Health health = indicator.health();

    // Assert
    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails().get("jwksUri")).isEqualTo(wireMockServer.baseUrl() + "/certs");
    assertThat(health.getDetails().get("error")).isNotNull();
  }

  @Test
  @DisplayName("should return DOWN when JWKS endpoint is unreachable")
  void should_returnDown_when_jwksUnreachable() {
    // Arrange — use a port that nothing is listening on
    int port = wireMockServer.port();
    wireMockServer.stop();
    GatewayProperties properties = buildProperties("http://localhost:" + port + "/certs");
    JwksHealthIndicator indicator = new JwksHealthIndicator(properties, RestClient.builder());

    // Act
    Health health = indicator.health();

    // Assert
    assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    assertThat(health.getDetails()).containsKey("error");
  }

  private GatewayProperties buildProperties(String jwksUri) {
    return new GatewayProperties(
        new GatewayProperties.JwtConfig(jwksUri, "test-issuer", "test-audience", 5),
        Map.of(),
        new GatewayProperties.PermissionsConfig(Map.of()),
        new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
        new GatewayProperties.InstalledCacheConfig(5, 30),
        new GatewayProperties.WebhookConfig(3, 1000, 2.0, 8000, null, null),
        new GatewayProperties.Bc02Config("http://localhost:8081"),
        null);
  }
}
