package com.adapstory.gateway.client;

import com.adapstory.gateway.config.GatewayProperties;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

/**
 * Test subclass of {@link PermissionFetchClient} that replaces the internally built {@code
 * RestClient} and {@code CircuitBreaker} with test doubles after construction.
 *
 * <p>Needed because Spring 7 requires a single visible constructor for auto-wiring, so the
 * production class exposes only one public constructor. Test setup injects mocks via reflection.
 */
class FakePermissionFetchClient extends PermissionFetchClient {

  FakePermissionFetchClient(RestClient restClient, CircuitBreaker circuitBreaker) {
    super(stubProperties(), CircuitBreakerRegistry.ofDefaults());
    ReflectionTestUtils.setField(this, "restClient", restClient);
    ReflectionTestUtils.setField(this, "circuitBreaker", circuitBreaker);
  }

  private static GatewayProperties stubProperties() {
    return new GatewayProperties(
        null,
        null,
        null,
        null,
        null,
        null,
        new GatewayProperties.Bc02Config("http://stub-bc02"),
        null);
  }
}
