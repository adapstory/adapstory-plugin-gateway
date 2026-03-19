package com.adapstory.gateway.config;

import java.net.URI;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Health indicator для проверки доступности Keycloak JWKS endpoint.
 *
 * <p>Используется readiness probe для проверки, что Plugin Gateway может валидировать JWT токены.
 */
@Component
public class JwksHealthIndicator implements HealthIndicator {

  private final GatewayProperties properties;
  private final RestClient restClient;

  public JwksHealthIndicator(GatewayProperties properties, RestClient.Builder restClientBuilder) {
    this.properties = properties;
    this.restClient = restClientBuilder.build();
  }

  @Override
  public Health health() {
    String jwksUri = properties.jwt().jwksUri();
    try {
      restClient.get().uri(URI.create(jwksUri)).retrieve().toBodilessEntity();

      return Health.up().withDetail("jwksUri", jwksUri).build();
    } catch (Exception ex) {
      return Health.down()
          .withDetail("jwksUri", jwksUri)
          .withDetail("error", ex.getMessage())
          .build();
    }
  }
}
