package com.adapstory.gateway.client;

import com.adapstory.gateway.config.GatewayProperties;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * REST-клиент для проверки установки плагина для тенанта через BC-02.
 *
 * <p>Вызывает {@code GET /internal/api/v1/plugins/{pluginId}/installed?tenant_id={tenantId}}.
 * Обёрнут circuit breaker {@code bc02-installed-check} (ADR-4). При сбое BC-02 возвращает {@link
 * Optional#empty()} — вызывающий код реализует fail-open с warning log.
 */
@Component
public class InstalledPluginFetchClient {

  private static final Logger log = LoggerFactory.getLogger(InstalledPluginFetchClient.class);
  private static final String CB_NAME = "bc02-installed-check";
  private static final String INSTALLED_PATH =
      "/internal/api/v1/plugins/{pluginId}/installed?tenant_id={tenantId}";

  private static final Pattern PLUGIN_ID_PATTERN =
      Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]{1,123}[a-zA-Z0-9]$");

  private static final int CONNECT_TIMEOUT_MS = 3000;
  private static final int READ_TIMEOUT_MS = 3000;

  private final RestClient restClient;
  private final CircuitBreaker circuitBreaker;
  private final ObjectMapper objectMapper;

  /**
   * Создаёт клиент с RestClient + Circuit Breaker.
   *
   * @param properties конфигурация Gateway (содержит baseUrl BC-02)
   * @param circuitBreakerRegistry реестр circuit breakers
   * @param objectMapper Jackson ObjectMapper для парсинга ответа
   */
  public InstalledPluginFetchClient(
      GatewayProperties properties,
      CircuitBreakerRegistry circuitBreakerRegistry,
      ObjectMapper objectMapper) {
    Objects.requireNonNull(properties, "properties must not be null");
    Objects.requireNonNull(circuitBreakerRegistry, "circuitBreakerRegistry must not be null");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");

    var factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS));
    factory.setReadTimeout(Duration.ofMillis(READ_TIMEOUT_MS));

    this.restClient =
        RestClient.builder()
            .baseUrl(properties.bc02().baseUrl())
            .requestFactory(factory)
            .build();

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

  /**
   * Проверяет установку плагина для тенанта через BC-02.
   *
   * @param pluginId идентификатор плагина
   * @param tenantId идентификатор тенанта
   * @return Optional.of(true) если установлен, Optional.of(false) если нет, Optional.empty() при
   *     ошибке
   */
  public Optional<Boolean> fetchInstalledStatus(String pluginId, String tenantId) {
    Objects.requireNonNull(pluginId, "pluginId must not be null");
    Objects.requireNonNull(tenantId, "tenantId must not be null");

    if (!PLUGIN_ID_PATTERN.matcher(pluginId).matches()) {
      log.warn("Invalid pluginId format: {}", pluginId);
      return Optional.of(false);
    }

    try {
      return circuitBreaker.executeSupplier(() -> doFetch(pluginId, tenantId));
    } catch (CallNotPermittedException e) {
      log.warn(
          "Circuit breaker {} is OPEN, cannot check installed status: pluginId={}, tenantId={}",
          CB_NAME,
          pluginId,
          tenantId);
      return Optional.empty();
    } catch (Exception e) {
      log.error(
          "Failed to check installed status: pluginId={}, tenantId={}, error={}",
          pluginId,
          tenantId,
          e.getMessage());
      return Optional.empty();
    }
  }

  private Optional<Boolean> doFetch(String pluginId, String tenantId) {
    String requestId = Optional.ofNullable(MDC.get("request-id")).orElse(UUID.randomUUID().toString());
    String correlationId =
        Optional.ofNullable(MDC.get("correlation-id")).orElse(UUID.randomUUID().toString());

    try {
      String responseBody =
          restClient
              .get()
              .uri(INSTALLED_PATH, pluginId, tenantId)
              .header("X-Request-Id", requestId)
              .header("X-Correlation-Id", correlationId)
              .retrieve()
              .body(String.class);

      if (responseBody == null) {
        return Optional.of(false);
      }

      JsonNode root = objectMapper.readTree(responseBody);
      JsonNode data = root.get("data");
      if (data == null || data.isNull()) {
        return Optional.of(false);
      }
      boolean installed = data.get("installed") != null && data.get("installed").booleanValue();
      return Optional.of(installed);
    } catch (RestClientException e) {
      log.warn(
          "REST call to BC-02 installed check failed: pluginId={}, tenantId={}, error={}",
          pluginId,
          tenantId,
          e.getMessage());
      throw e;
    } catch (Exception e) {
      log.warn("Failed to parse BC-02 installed response: {}", e.getMessage());
      return Optional.of(false);
    }
  }
}
