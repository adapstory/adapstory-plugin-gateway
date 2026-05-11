package com.adapstory.gateway.client;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.Bc02ClientConfig;
import com.adapstory.gateway.dto.PluginPermissionsResponse;
import com.adapstory.gateway.util.FetchClientUtils;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * REST-клиент для запроса manifest permissions плагина из BC-02.
 *
 * <p>Вызывает {@code GET /api/bc-02/plugin-lifecycle/v1/{pluginId}/permissions} с обязательными
 * заголовками трассировки. Обёрнут circuit breaker {@code bc02-permissions} (ADR-4). При сбое BC-02
 * или открытом CB возвращает {@link Optional#empty()} — вызывающий код реализует fail-closed.
 */
@Component
public class PermissionFetchClient {

  private static final Logger log = LoggerFactory.getLogger(PermissionFetchClient.class);
  private static final String CB_NAME = "bc02-permissions";
  private static final String PERMISSIONS_PATH =
      "/api/bc-02/plugin-lifecycle/v1/{pluginId}/permissions";

  private final RestClient restClient;
  private final CircuitBreaker circuitBreaker;

  /**
   * Creates client with RestClient + Circuit Breaker using {@link Bc02ClientConfig} factory.
   *
   * @param bc02ClientConfig shared BC-02 client configuration
   * @param restClientBuilder Spring auto-configured RestClient builder
   * @param circuitBreakerRegistry circuit breaker registry
   */
  @Autowired
  public PermissionFetchClient(
      Bc02ClientConfig bc02ClientConfig,
      RestClient.Builder restClientBuilder,
      CircuitBreakerRegistry circuitBreakerRegistry) {
    Objects.requireNonNull(bc02ClientConfig, "bc02ClientConfig must not be null");
    Objects.requireNonNull(restClientBuilder, "restClientBuilder must not be null");
    Objects.requireNonNull(circuitBreakerRegistry, "circuitBreakerRegistry must not be null");

    this.restClient = bc02ClientConfig.createBc02RestClient(restClientBuilder);
    this.circuitBreaker =
        bc02ClientConfig.createBc02CircuitBreaker(circuitBreakerRegistry, CB_NAME);
  }

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
        Optional.ofNullable(MDC.get(IntegrationHeaders.REQUEST_ID))
            .orElse(UUID.randomUUID().toString());
    String correlationId =
        Optional.ofNullable(MDC.get(IntegrationHeaders.CORRELATION_ID))
            .orElse(UUID.randomUUID().toString());

    PluginPermissionsResponse response =
        restClient
            .get()
            .uri(PERMISSIONS_PATH, pluginId)
            .header(IntegrationHeaders.HEADER_REQUEST_ID, requestId)
            .header(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId)
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
    FetchClientUtils.validatePluginId(pluginId);
  }
}
