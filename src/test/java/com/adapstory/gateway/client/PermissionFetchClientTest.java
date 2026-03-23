package com.adapstory.gateway.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withResourceNotFound;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

@DisplayName("PermissionFetchClient")
class PermissionFetchClientTest {

  private static final String PLUGIN_ID = "adapstory.assessment.quiz";
  private static final String BASE_URL = "http://localhost:8081";
  private static final String PERMISSIONS_URI =
      BASE_URL + "/api/bc-02/plugin-lifecycle/v1/plugins/" + PLUGIN_ID + "/permissions";

  private static final String RESPONSE_WITH_PERMISSIONS =
      """
      {
        "data": {
          "pluginId": "adapstory.assessment.quiz",
          "permissions": ["read:collections", "write:events"]
        },
        "messages": [],
        "error": null
      }
      """;

  private static final String RESPONSE_EMPTY_PERMISSIONS =
      """
      {
        "data": {
          "pluginId": "adapstory.assessment.quiz",
          "permissions": []
        },
        "messages": [],
        "error": null
      }
      """;

  private PermissionFetchClient client;
  private MockRestServiceServer mockServer;

  @BeforeEach
  void setUp() {
    RestClient.Builder builder = RestClient.builder().baseUrl(BASE_URL);
    mockServer = MockRestServiceServer.bindTo(builder).build();

    CircuitBreakerConfig cbConfig =
        CircuitBreakerConfig.custom()
            .slidingWindowSize(2)
            .failureRateThreshold(50)
            .waitDurationInOpenState(Duration.ofSeconds(60))
            .minimumNumberOfCalls(2)
            .permittedNumberOfCallsInHalfOpenState(1)
            .build();

    CircuitBreakerRegistry registry = CircuitBreakerRegistry.of(cbConfig);
    CircuitBreaker cb = registry.circuitBreaker("bc02-permissions", cbConfig);

    client = PermissionFetchClient.forTest(builder.build(), cb);
  }

  @Nested
  @DisplayName("fetchPermissions")
  class FetchPermissions {

    @Test
    @DisplayName("should return permissions on successful BC-02 response")
    void should_return_permissions_on_success() {
      // Arrange
      mockServer
          .expect(requestTo(PERMISSIONS_URI))
          .andExpect(header("X-Request-Id", Matchers.notNullValue()))
          .andExpect(header("X-Correlation-Id", Matchers.notNullValue()))
          .andRespond(withSuccess(RESPONSE_WITH_PERMISSIONS, MediaType.APPLICATION_JSON));

      // Act
      Optional<List<String>> result = client.fetchPermissions(PLUGIN_ID);

      // Assert
      assertThat(result).isPresent();
      assertThat(result.get()).containsExactly("read:collections", "write:events");
      mockServer.verify();
    }

    @Test
    @DisplayName("should return empty list when plugin has no permissions")
    void should_return_empty_list_when_no_permissions() {
      // Arrange
      mockServer
          .expect(requestTo(PERMISSIONS_URI))
          .andRespond(withSuccess(RESPONSE_EMPTY_PERMISSIONS, MediaType.APPLICATION_JSON));

      // Act
      Optional<List<String>> result = client.fetchPermissions(PLUGIN_ID);

      // Assert
      assertThat(result).isPresent();
      assertThat(result.get()).isEmpty();
      mockServer.verify();
    }

    @Test
    @DisplayName("should return empty Optional when BC-02 returns server error")
    void should_return_empty_on_server_error() {
      // Arrange
      mockServer.expect(requestTo(PERMISSIONS_URI)).andRespond(withServerError());

      // Act
      Optional<List<String>> result = client.fetchPermissions(PLUGIN_ID);

      // Assert
      assertThat(result).isEmpty();
      mockServer.verify();
    }

    @Test
    @DisplayName("should return empty Optional when circuit breaker is open")
    void should_return_empty_when_circuit_breaker_open() {
      // Arrange — trigger failures to open CB (minimumNumberOfCalls=2, threshold=50%)
      mockServer.expect(requestTo(PERMISSIONS_URI)).andRespond(withServerError());
      mockServer.expect(requestTo(PERMISSIONS_URI)).andRespond(withServerError());

      client.fetchPermissions(PLUGIN_ID); // failure 1
      client.fetchPermissions(PLUGIN_ID); // failure 2 → CB opens

      // Act — CB is open, no HTTP call made
      Optional<List<String>> result = client.fetchPermissions(PLUGIN_ID);

      // Assert
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("should return empty Optional when BC-02 returns 404")
    void should_return_empty_on_not_found() {
      // Arrange
      mockServer.expect(requestTo(PERMISSIONS_URI)).andRespond(withResourceNotFound());

      // Act
      Optional<List<String>> result = client.fetchPermissions(PLUGIN_ID);

      // Assert
      assertThat(result).isEmpty();
      mockServer.verify();
    }

    @Test
    @DisplayName("should return empty list when BC-02 returns null data")
    void should_return_empty_list_when_null_data() {
      // Arrange
      String responseNullData =
          """
          {
            "data": null,
            "messages": [],
            "error": null
          }
          """;
      mockServer
          .expect(requestTo(PERMISSIONS_URI))
          .andRespond(withSuccess(responseNullData, MediaType.APPLICATION_JSON));

      // Act
      Optional<List<String>> result = client.fetchPermissions(PLUGIN_ID);

      // Assert
      assertThat(result).isPresent();
      assertThat(result.get()).isEmpty();
      mockServer.verify();
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for null pluginId")
    void should_throw_on_null_pluginId() {
      assertThatThrownBy(() -> client.fetchPermissions(null))
          .isInstanceOf(NullPointerException.class)
          .hasMessageContaining("pluginId must not be null");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for blank pluginId")
    void should_throw_on_blank_pluginId() {
      assertThatThrownBy(() -> client.fetchPermissions(""))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("pluginId must not be blank");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for invalid pluginId format")
    void should_throw_on_invalid_pluginId_format() {
      assertThatThrownBy(() -> client.fetchPermissions("../../etc/passwd"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("pluginId format invalid");
    }
  }
}
