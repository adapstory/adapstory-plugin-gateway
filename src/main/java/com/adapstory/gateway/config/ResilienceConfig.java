package com.adapstory.gateway.config;

import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Конфигурация Resilience4j circuit breaker для Plugin Gateway.
 *
 * <p>Один circuit breaker на каждый целевой BC. Config: failureRateThreshold=50%,
 * waitDurationInOpenState=30s, slidingWindowSize=10. Fallback: 503 Service Unavailable с Pattern 8
 * error format.
 */
@Configuration
public class ResilienceConfig {

  @Bean
  CircuitBreakerRegistry circuitBreakerRegistry() {
    CircuitBreakerConfig defaultConfig =
        CircuitBreakerConfig.custom()
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(30))
            .slidingWindowSize(10)
            .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
            .permittedNumberOfCallsInHalfOpenState(3)
            .minimumNumberOfCalls(5)
            .build();

    return CircuitBreakerRegistry.of(defaultConfig);
  }
}
