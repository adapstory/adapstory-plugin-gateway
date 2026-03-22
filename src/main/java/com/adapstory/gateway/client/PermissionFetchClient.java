package com.adapstory.gateway.client;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.PluginPermissionsResponse;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

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

  /** Допустимый формат pluginId: tri-part (vendor.category.name) или UUID. */
  private static final Pattern PLUGIN_ID_PATTERN =
      Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]{1,123}[a-zA-Z0-9]$");

  private static final int CONNECT_TIMEOUT_MS = 3000;
  private static final int READ_TIMEOUT_MS = 3000;

  private RestClient restClient;
  private CircuitBreaker circuitBreaker;

  /**
   * Создаёт клиент с RestClient + Circuit Breaker.
   *
   * @param properties конфигурация Gateway (содержит baseUrl BC-02)
   * @param circuitBreakerRegistry реестр circuit breakers
   */
  @Autowired
  public PermissionFetchClient(
      GatewayProperties properties, CircuitBreakerRegistry circuitBreakerRegistry) {
    Objects.requireNonNull(properties, "properties must not be null");
    Objects.requireNonNull(circuitBreakerRegistry, "circuitBreakerRegistry must not be null");

    var factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS));
    factory.setReadTimeout(Duration.ofMillis(READ_TIMEOUT_MS));

    this.restClient =
        RestClient.builder().baseUrl(properties.bc02().baseUrl()).requestFactory(factory).build();

    this.circuitBreaker =
        circuitBreakerRegistry.circuitBreaker(
            CB_NAME,
            CircuitBreakerConfig.custom()
                .slidingWindowSize(20)
                .failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(10))
                .permittedNumberOfCallsInHalfOpenState(3)
                .slowCallDurationThreshold(Duration.ofSeconds(5))
                .minimumNumberOfCalls(5)
                .build());
  }

  /** Package-private factory for unit tests — injects pre-built RestClient and CircuitBreaker. */
  static PermissionFetchClient forTest(RestClient restClient, CircuitBreaker circuitBreaker) {
    var client = new PermissionFetchClient();
    client.restClient = restClient;
    client.circuitBreaker = circuitBreaker;
    return client;
  }

  private PermissionFetchClient() {}

  /**
   * Запрашивает список manifest permissions плагина из BC-02.
   *
   * @param pluginId идентификатор плагина (tri-part или UUID)
   * @return {@code Optional<List<String>>} со scope-именами; {@code empty()} при сбое BC-02 или
   *     открытом circuit breaker
   * @throws IllegalArgumentException если pluginId null, пустой или не соответствует формату
   */
  public Optional<List<String>> fetchPermissions(String pluginId) {
    validatePluginId(pluginId);
    try {
      return circuitBreaker.executeSupplier(() -> doFetch(pluginId));
    } catch (CallNotPermittedException e) {
      log.debug("Circuit breaker open for BC-02 permissions, plugin '{}'", pluginId);
      return Optional.empty();
    } catch (RestClientException e) {
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
    return Optional.of(permissions);
  }

  public static void validatePluginId(String pluginId) {
    Objects.requireNonNull(pluginId, "pluginId must not be null");
    if (pluginId.isBlank()) {
      throw new IllegalArgumentException("pluginId must not be blank");
    }
    if (!PLUGIN_ID_PATTERN.matcher(pluginId).matches()) {
      throw new IllegalArgumentException(
          "pluginId format invalid (expected tri-part or UUID): " + pluginId);
    }
  }
}
