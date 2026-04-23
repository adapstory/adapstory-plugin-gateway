package com.adapstory.gateway.client;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.starter.web.auth.ServiceHeaderInterceptor;
import com.adapstory.starter.web.auth.ServiceTokenPort;
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
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * REST-клиент для проверки установки плагина для тенанта через BC-02.
 *
 * <p>Вызывает {@code GET /api/bc-02/plugin-lifecycle/v1/{pluginId}/installed} с {@code X-Tenant-Id}
 * header. Обёрнут circuit breaker {@code bc02-installed-check} (ADR-4). При сбое BC-02 возвращает
 * {@link Optional#empty()} — вызывающий код обязан трактовать это как installation-verification
 * unavailable и fail-close на gateway edge.
 */
@Component
public class InstalledPluginFetchClient {

  private static final Logger log = LoggerFactory.getLogger(InstalledPluginFetchClient.class);
  private static final String CB_NAME = "bc02-installed-check";
  private static final String INSTALLED_PATH =
      "/api/bc-02/plugin-lifecycle/v1/{pluginId}/installed";

  private static final Pattern PLUGIN_ID_PATTERN =
      Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]{1,123}[a-zA-Z0-9]$");

  private static final Pattern UUID_PATTERN =
      Pattern.compile(
          "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

  private static final int CONNECT_TIMEOUT_MS = 3000;
  private static final int READ_TIMEOUT_MS = 3000;
  private static final String TARGET_AUDIENCE = "adapstory-bc02-service";
  private static final String SOURCE_SERVICE = "plugin-gateway";
  private static final String DEFAULT_CLIENT_ID = "adapstory-plugin-gateway";

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
  @Autowired
  public InstalledPluginFetchClient(
      RestClient.Builder restClientBuilder,
      GatewayProperties properties,
      CircuitBreakerRegistry circuitBreakerRegistry,
      ObjectProvider<ServiceTokenPort> serviceTokenPort,
      ObjectMapper objectMapper,
      @Value("${adapstory.service-auth.client-id:" + DEFAULT_CLIENT_ID + "}") String clientId) {
    Objects.requireNonNull(restClientBuilder, "restClientBuilder must not be null");
    Objects.requireNonNull(properties, "properties must not be null");
    Objects.requireNonNull(circuitBreakerRegistry, "circuitBreakerRegistry must not be null");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");

    var factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS));
    factory.setReadTimeout(Duration.ofMillis(READ_TIMEOUT_MS));

    RestClient.Builder builder =
        restClientBuilder.baseUrl(properties.bc02().baseUrl()).requestFactory(factory);
    ServiceTokenPort tokenPort = serviceTokenPort.getIfAvailable();
    if (tokenPort != null) {
      builder.requestInterceptor(
          new ServiceHeaderInterceptor(tokenPort, TARGET_AUDIENCE, SOURCE_SERVICE, clientId));
    } else {
      builder.requestInterceptor(
          (request, body, execution) -> {
            propagateHeader(
                request,
                IntegrationHeaders.HEADER_REQUEST_ID,
                MDC.get(IntegrationHeaders.REQUEST_ID),
                UUID.randomUUID().toString());
            propagateHeader(
                request,
                IntegrationHeaders.HEADER_CORRELATION_ID,
                MDC.get(IntegrationHeaders.CORRELATION_ID),
                UUID.randomUUID().toString());
            request.getHeaders().set(IntegrationHeaders.HEADER_USER_ID, "service:" + SOURCE_SERVICE);
            request.getHeaders().set(IntegrationHeaders.HEADER_SOURCE_SERVICE, SOURCE_SERVICE);
            return execution.execute(request, body);
          });
    }

    this.restClient = builder.build();

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

  /** Конструктор для тестов — принимает готовые RestClient и CircuitBreaker. */
  InstalledPluginFetchClient(
      RestClient restClient, CircuitBreaker circuitBreaker, ObjectMapper objectMapper) {
    this.restClient = restClient;
    this.circuitBreaker = circuitBreaker;
    this.objectMapper = objectMapper;
  }

  /**
   * Проверяет установку плагина для тенанта через BC-02.
   *
   * @param pluginId идентификатор плагина
   * @param tenantId идентификатор тенанта (UUID format)
   * @return Optional.of(true) если установлен, Optional.of(false) если нет, Optional.empty() если
   *     verification недоступна и вызывающий код должен fail-close
   * @throws IllegalArgumentException если pluginId не соответствует формату
   */
  public Optional<Boolean> fetchInstalledStatus(String pluginId, String tenantId) {
    Objects.requireNonNull(pluginId, "pluginId must not be null");
    Objects.requireNonNull(tenantId, "tenantId must not be null");

    // H-5: throw on invalid pluginId (programming error, not "not installed")
    if (!PLUGIN_ID_PATTERN.matcher(pluginId).matches()) {
      throw new IllegalArgumentException(
          "pluginId format invalid (expected tri-part or UUID): " + pluginId);
    }

    // H-7: validate tenantId as UUID to prevent injection via URL/Redis key
    if (!UUID_PATTERN.matcher(tenantId).matches()) {
      throw new IllegalArgumentException("tenantId must be a valid UUID: " + tenantId);
    }

    try {
      return circuitBreaker.executeSupplier(() -> doFetch(pluginId, tenantId));
    } catch (CallNotPermittedException ex) {
      log.warn(
          "Circuit breaker {} is OPEN, cannot check installed status: pluginId={}, tenantId={}, reason={}",
          CB_NAME,
          pluginId,
          tenantId,
          ex.getMessage());
      return Optional.empty();
    } catch (RestClientException e) {
      log.warn(
          "Failed to check installed status: pluginId={}, tenantId={}, error={}",
          pluginId,
          tenantId,
          e.getMessage());
      return Optional.empty();
    } catch (Exception e) {
      // M-6: Catch any other exception (e.g., IOException from JSON parsing inside CB)
      log.warn(
          "Unexpected error checking installed status: pluginId={}, tenantId={}, error={}",
          pluginId,
          tenantId,
          e.getMessage());
      return Optional.empty();
    }
  }

  private Optional<Boolean> doFetch(String pluginId, String tenantId) {
    String requestId =
        Optional.ofNullable(MDC.get(IntegrationHeaders.REQUEST_ID))
            .orElse(UUID.randomUUID().toString());
    String correlationId =
        Optional.ofNullable(MDC.get(IntegrationHeaders.CORRELATION_ID))
            .orElse(UUID.randomUUID().toString());

    String responseBody;
    try {
      responseBody =
          restClient
              .get()
              .uri(INSTALLED_PATH, pluginId)
              .header(IntegrationHeaders.HEADER_TENANT_ID, tenantId)
              .header(IntegrationHeaders.HEADER_REQUEST_ID, requestId)
              .header(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId)
              .retrieve()
              .body(String.class);
    } catch (org.springframework.web.client.HttpClientErrorException.NotFound ex) {
      // M-10: BC-02 returns 404 = plugin does not exist → treat as "not installed"
      log.debug(
          "BC-02 returned 404 for installed check (plugin not found): pluginId={}, tenantId={}, status={}",
          pluginId,
          tenantId,
          ex.getStatusCode());
      return Optional.of(false);
    }

    // H-6: null body is an unexpected/broken response → verification unavailable
    if (responseBody == null) {
      log.warn(
          "BC-02 returned null body for installed check: pluginId={}, tenantId={}",
          pluginId,
          tenantId);
      return Optional.empty();
    }

    try {
      JsonNode root = objectMapper.readTree(responseBody);
      JsonNode data = root.get("data");
      if (data == null || data.isNull()) {
        return Optional.of(false);
      }
      boolean installed = data.get("installed") != null && data.get("installed").booleanValue();
      return Optional.of(installed);
    } catch (Exception e) {
      // C-2: parse failure → verification unavailable (not "not installed")
      log.warn("Failed to parse BC-02 installed response: {}", e.getMessage());
      return Optional.empty();
    }
  }

  private static void propagateHeader(
      HttpRequest request, String headerName, String currentValue, String defaultValue) {
    String value = currentValue != null && !currentValue.isBlank() ? currentValue : defaultValue;
    request.getHeaders().set(headerName, value);
  }
}
