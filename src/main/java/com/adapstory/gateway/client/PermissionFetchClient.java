package com.adapstory.gateway.client;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.PluginPermissionsResponse;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * REST-клиент для запроса manifest permissions плагина из BC-02.
 *
 * <p>Вызывает {@code GET /internal/api/v1/plugins/{pluginId}/permissions} с обязательными
 * заголовками трассировки. Обёрнут circuit breaker {@code bc02-permissions} (ADR-4). При сбое BC-02
 * или открытом CB возвращает {@link Optional#empty()} — вызывающий код реализует fail-closed.
 */
@Component
public class PermissionFetchClient {

  private static final Logger log = LoggerFactory.getLogger(PermissionFetchClient.class);
  private static final String CB_NAME = "bc02-permissions";
  private static final String PERMISSIONS_PATH = "/internal/api/v1/plugins/{pluginId}/permissions";

  private final RestClient restClient;
  private final CircuitBreaker circuitBreaker;

  @Autowired
  public PermissionFetchClient(
      GatewayProperties properties, CircuitBreakerRegistry circuitBreakerRegistry) {
    this(
        RestClient.builder().baseUrl(properties.bc02().baseUrl()).build(),
        createCircuitBreaker(circuitBreakerRegistry));
  }

  /** Конструктор для тестов — принимает готовые RestClient и CircuitBreaker. */
  PermissionFetchClient(RestClient restClient, CircuitBreaker circuitBreaker) {
    this.restClient = restClient;
    this.circuitBreaker = circuitBreaker;
  }

  /**
   * Запрашивает список manifest permissions плагина из BC-02.
   *
   * @param pluginId идентификатор плагина (tri-part или UUID)
   * @return {@code Optional<List<String>>} со scope-именами; {@code empty()} при сбое BC-02 или
   *     открытом circuit breaker
   */
  public Optional<List<String>> fetchPermissions(String pluginId) {
    try {
      return circuitBreaker.executeSupplier(() -> doFetch(pluginId));
    } catch (Exception e) {
      log.warn(
          "Failed to fetch permissions from BC-02 for plugin '{}': {}", pluginId, e.getMessage());
      return Optional.empty();
    }
  }

  private Optional<List<String>> doFetch(String pluginId) {
    String requestId =
        Optional.ofNullable(MDC.get("request-id")).orElse(UUID.randomUUID().toString());
    String correlationId =
        Optional.ofNullable(MDC.get("correlation-id")).orElse(UUID.randomUUID().toString());

    PluginPermissionsResponse response =
        restClient
            .get()
            .uri(PERMISSIONS_PATH, pluginId)
            .header("X-Request-Id", requestId)
            .header("X-Correlation-Id", correlationId)
            .retrieve()
            .body(PluginPermissionsResponse.class);

    if (response == null || response.data() == null) {
      log.warn("BC-02 returned null response for plugin '{}'", pluginId);
      return Optional.of(List.of());
    }

    List<String> permissions = response.data().permissions();
    log.debug("Fetched {} permissions from BC-02 for plugin '{}'", permissions.size(), pluginId);
    return Optional.of(permissions != null ? permissions : List.of());
  }

  private static CircuitBreaker createCircuitBreaker(CircuitBreakerRegistry registry) {
    CircuitBreakerConfig cbConfig =
        CircuitBreakerConfig.custom()
            .slidingWindowSize(20)
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(10))
            .permittedNumberOfCallsInHalfOpenState(3)
            .slowCallDurationThreshold(Duration.ofSeconds(5))
            .minimumNumberOfCalls(5)
            .build();

    return registry.circuitBreaker(CB_NAME, cbConfig);
  }
}
