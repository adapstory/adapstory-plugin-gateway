package com.adapstory.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import com.github.tomakehurst.wiremock.http.Fault;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;

/**
 * Интеграционные тесты: Circuit Breaker (AC#3). Использует быструю конфигурацию CB и WireMock Fault
 * injection для симуляции connection failures.
 */
@Import(PluginGatewayCircuitBreakerIT.TestCbConfig.class)
class PluginGatewayCircuitBreakerIT extends AbstractGatewayIntegrationTest {

  private static final String PLUGIN_ID = "adapstory.education_module.ai-grader";
  private static final String TENANT_ID = "tenant-uuid";

  @Autowired private CircuitBreakerRegistry circuitBreakerRegistry;

  // NB: intentionally NOT @Configuration — @Import handles bean registration,
  // while @Configuration on an inner class would override the main SpringBootApplication context.
  static class TestCbConfig {
    @Bean
    @Primary
    CircuitBreakerRegistry testCircuitBreakerRegistry() {
      CircuitBreakerConfig config =
          CircuitBreakerConfig.custom()
              .failureRateThreshold(50)
              .waitDurationInOpenState(Duration.ofSeconds(2))
              .slidingWindowSize(4)
              .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
              .permittedNumberOfCallsInHalfOpenState(1)
              .minimumNumberOfCalls(2)
              .build();
      return CircuitBreakerRegistry.of(config);
    }
  }

  @BeforeEach
  void resetCircuitBreakers() {
    circuitBreakerRegistry.getAllCircuitBreakers().forEach(cb -> cb.reset());
    BC_WIREMOCK.resetAll();
  }

  @Test
  @DisplayName("AC#3: Connection failures → circuit opens → 503 with circuitBreakerState: OPEN")
  void repeatedFailures_circuitOpens_returns503() {
    // Arrange: WireMock causes connection reset (simulates unreachable target BC)
    BC_WIREMOCK.stubFor(
        get(urlPathEqualTo("/api/content/v1/materials/123"))
            .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    // Act: send enough requests to trip the circuit breaker
    for (int i = 0; i < 2; i++) {
      try {
        testClient
            .get()
            .uri("/gateway/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);
      } catch (HttpServerErrorException | ResourceAccessException ignored) {
        // 502 Bad Gateway expected
      }
    }

    // Assert: next request should get 503 (circuit open — CallNotPermittedException)
    assertThatThrownBy(
            () ->
                testClient
                    .get()
                    .uri("/gateway/api/content/v1/materials/123")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                    .retrieve()
                    .toEntity(String.class))
        .isInstanceOf(HttpServerErrorException.class)
        .satisfies(
            ex -> {
              HttpServerErrorException hse = (HttpServerErrorException) ex;
              assertThat(hse.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
              String body = hse.getResponseBodyAsString();
              assertThat(body).contains("circuitBreakerState");
              assertThat(body).contains("OPEN");
            });
  }

  @Test
  @DisplayName("AC#3: After circuit opens, wait for half-open → success closes circuit")
  void circuitOpensAndRecovers() {
    // Arrange: first make circuit open with connection failures
    BC_WIREMOCK.stubFor(
        get(urlPathEqualTo("/api/content/v1/materials/123"))
            .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

    String jwt = buildValidJwt(PLUGIN_ID, TENANT_ID, List.of("content.read"), "CORE");

    for (int i = 0; i < 2; i++) {
      try {
        testClient
            .get()
            .uri("/gateway/api/content/v1/materials/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
            .retrieve()
            .toEntity(String.class);
      } catch (HttpServerErrorException | ResourceAccessException ignored) {
      }
    }

    // Switch WireMock to success before waiting, so half-open probe can succeed
    BC_WIREMOCK.resetAll();
    BC_WIREMOCK.stubFor(
        get(urlPathEqualTo("/api/content/v1/materials/123"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"id\":\"123\"}")));

    // Wait for half-open transition (waitDurationInOpenState=2s) then verify recovery.
    // Awaitility polls the actual HTTP endpoint which triggers the half-open probe.
    await()
        .atMost(Duration.ofSeconds(10))
        .pollInterval(Duration.ofMillis(500))
        .pollDelay(Duration.ofSeconds(2))
        .untilAsserted(
            () -> {
              var response =
                  testClient
                      .get()
                      .uri("/gateway/api/content/v1/materials/123")
                      .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                      .retrieve()
                      .toEntity(String.class);
              assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            });
  }
}
