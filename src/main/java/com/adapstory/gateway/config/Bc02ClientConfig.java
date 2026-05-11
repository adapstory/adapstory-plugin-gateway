package com.adapstory.gateway.config;

import com.adapstory.gateway.util.FetchClientUtils;
import com.adapstory.starter.web.auth.ServiceHeaderInterceptor;
import com.adapstory.starter.web.auth.ServiceTokenPort;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.time.Duration;
import java.util.Objects;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Shared configuration factory for BC-02 REST clients.
 *
 * <p>Centralises {@link RestClient} and {@link CircuitBreaker} creation, eliminating ~80 lines of
 * duplicated configuration between {@code InstalledPluginFetchClient} and {@code
 * PermissionFetchClient} (GRASP audit LC-1, LC-2, PF-1).
 */
@Configuration
public class Bc02ClientConfig {

  private static final String TARGET_AUDIENCE = "adapstory-bc02-service";
  private static final String DEFAULT_CLIENT_ID = "adapstory-plugin-gateway";

  private static final int CONNECT_TIMEOUT_MS = 3000;
  private static final int READ_TIMEOUT_MS = 3000;

  private static final CircuitBreakerConfig BC02_CB_CONFIG =
      CircuitBreakerConfig.custom()
          .slidingWindowSize(20)
          .failureRateThreshold(50)
          .waitDurationInOpenState(Duration.ofSeconds(10))
          .permittedNumberOfCallsInHalfOpenState(3)
          .slowCallDurationThreshold(Duration.ofSeconds(5))
          .minimumNumberOfCalls(5)
          .build();

  private final GatewayProperties properties;
  private final ObjectProvider<ServiceTokenPort> serviceTokenPort;
  private final String clientId;

  public Bc02ClientConfig(
      GatewayProperties properties,
      ObjectProvider<ServiceTokenPort> serviceTokenPort,
      @Value("${adapstory.service-auth.client-id:" + DEFAULT_CLIENT_ID + "}") String clientId) {
    this.properties = properties;
    this.serviceTokenPort = serviceTokenPort;
    this.clientId = clientId;
  }

  /**
   * Creates a pre-configured {@link RestClient} for BC-02 communication.
   *
   * <p>Sets base URL from {@code gateway.bc02.baseUrl}, connect/read timeouts (3s), and service
   * token interceptor with fallback.
   *
   * @param restClientBuilder Spring auto-configured builder
   * @return configured RestClient
   */
  public RestClient createBc02RestClient(RestClient.Builder restClientBuilder) {
    Objects.requireNonNull(restClientBuilder, "restClientBuilder must not be null");

    var factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS));
    factory.setReadTimeout(Duration.ofMillis(READ_TIMEOUT_MS));

    RestClient.Builder builder =
        restClientBuilder.baseUrl(properties.bc02().baseUrl()).requestFactory(factory);

    ServiceTokenPort tokenPort = serviceTokenPort.getIfAvailable();
    if (tokenPort != null) {
      builder.requestInterceptor(
          new ServiceHeaderInterceptor(
              tokenPort, TARGET_AUDIENCE, FetchClientUtils.HEADER_SOURCE_SERVICE, clientId));
    } else {
      builder.requestInterceptor(FetchClientUtils.fallbackHeaderInterceptor());
    }

    return builder.build();
  }

  /**
   * Creates or retrieves a {@link CircuitBreaker} for a BC-02 operation.
   *
   * <p>Uses a shared configuration: slidingWindowSize=20, failureRateThreshold=50%,
   * waitDurationInOpenState=10s.
   *
   * @param registry circuit breaker registry
   * @param name circuit breaker name (e.g., "bc02-installed-check")
   * @return configured circuit breaker
   */
  public CircuitBreaker createBc02CircuitBreaker(CircuitBreakerRegistry registry, String name) {
    return registry.circuitBreaker(name, BC02_CB_CONFIG);
  }

  /** Returns the shared BC-02 circuit breaker configuration. */
  public static CircuitBreakerConfig circuitBreakerConfig() {
    return BC02_CB_CONFIG;
  }
}
