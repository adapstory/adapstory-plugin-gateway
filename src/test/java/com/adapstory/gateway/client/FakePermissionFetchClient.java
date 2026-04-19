package com.adapstory.gateway.client;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.springframework.web.client.RestClient;

/**
 * Test subclass of {@link PermissionFetchClient} that replaces the internally built {@code
 * RestClient} and {@code CircuitBreaker} with test doubles.
 */
class FakePermissionFetchClient extends PermissionFetchClient {

  FakePermissionFetchClient(RestClient restClient, CircuitBreaker circuitBreaker) {
    super(restClient, circuitBreaker);
  }
}
