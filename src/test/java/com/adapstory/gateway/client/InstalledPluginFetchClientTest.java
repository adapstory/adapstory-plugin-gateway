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
import java.util.Optional;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Тесты InstalledPluginFetchClient: проверка установки плагина для тенанта через BC-02.
 *
 * <p>Покрывает: успешные ответы, 404, server error, circuit breaker, валидацию параметров, парсинг
 * различных структур ответа.
 */
@DisplayName("InstalledPluginFetchClient")
class InstalledPluginFetchClientTest {

  private static final String PLUGIN_ID = "adapstory.assessment.quiz";
  private static final String TENANT_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
  private static final String BASE_URL = "http://localhost:8081";
  private static final String INSTALLED_URI =
      BASE_URL + "/api/bc-02/plugin-lifecycle/v1/" + PLUGIN_ID + "/installed";

  private InstalledPluginFetchClient client;
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
    CircuitBreaker cb = registry.circuitBreaker("bc02-installed-check", cbConfig);

    client = new InstalledPluginFetchClient(builder.build(), cb, new ObjectMapper());
  }

  @Nested
  @DisplayName("fetchInstalledStatus — happy paths")
  class HappyPaths {

    @Test
    @DisplayName("should return true when plugin is installed")
    void should_returnTrue_when_pluginInstalled() {
      // Arrange
      String response =
          """
          {"data": {"installed": true, "version": "1.0.0"}, "messages": [], "error": null}
          """;
      mockServer
          .expect(requestTo(INSTALLED_URI))
          .andExpect(header("X-Request-Id", Matchers.notNullValue()))
          .andExpect(header("X-Correlation-Id", Matchers.notNullValue()))
          .andRespond(withSuccess(response, MediaType.APPLICATION_JSON));

      // Act
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(true);
      mockServer.verify();
    }

    @Test
    @DisplayName("should return false when plugin is not installed")
    void should_returnFalse_when_pluginNotInstalled() {
      // Arrange
      String response =
          """
          {"data": {"installed": false}, "messages": [], "error": null}
          """;
      mockServer
          .expect(requestTo(INSTALLED_URI))
          .andRespond(withSuccess(response, MediaType.APPLICATION_JSON));

      // Act
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(false);
      mockServer.verify();
    }

    @Test
    @DisplayName("should return false when data is null (M-10)")
    void should_returnFalse_when_dataIsNull() {
      // Arrange
      String response =
          """
          {"data": null, "messages": [], "error": null}
          """;
      mockServer
          .expect(requestTo(INSTALLED_URI))
          .andRespond(withSuccess(response, MediaType.APPLICATION_JSON));

      // Act
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(false);
      mockServer.verify();
    }

    @Test
    @DisplayName("should return false when installed field is missing")
    void should_returnFalse_when_installedFieldMissing() {
      // Arrange
      String response =
          """
          {"data": {"version": "1.0.0"}, "messages": [], "error": null}
          """;
      mockServer
          .expect(requestTo(INSTALLED_URI))
          .andRespond(withSuccess(response, MediaType.APPLICATION_JSON));

      // Act
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(false);
      mockServer.verify();
    }
  }

  @Nested
  @DisplayName("fetchInstalledStatus — error paths")
  class ErrorPaths {

    @Test
    @DisplayName("should return false when BC-02 returns 404 (M-10)")
    void should_returnFalse_when_bc02Returns404() {
      // Arrange
      mockServer.expect(requestTo(INSTALLED_URI)).andRespond(withResourceNotFound());

      // Act
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isPresent().contains(false);
      mockServer.verify();
    }

    @Test
    @DisplayName("should return empty Optional when BC-02 returns server error")
    void should_returnEmpty_when_serverError() {
      // Arrange
      mockServer.expect(requestTo(INSTALLED_URI)).andRespond(withServerError());

      // Act
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isEmpty();
      mockServer.verify();
    }

    @Test
    @DisplayName("should return empty Optional when response body is null (H-6)")
    void should_returnEmpty_when_responseBodyNull() {
      // Arrange — empty body
      mockServer
          .expect(requestTo(INSTALLED_URI))
          .andRespond(withSuccess("", MediaType.APPLICATION_JSON));

      // Act
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert — null/empty body → verification unavailable
      assertThat(result).isEmpty();
      mockServer.verify();
    }

    @Test
    @DisplayName("should return empty Optional when circuit breaker is open")
    void should_returnEmpty_when_circuitBreakerOpen() {
      // Arrange — trigger failures to open CB
      mockServer.expect(requestTo(INSTALLED_URI)).andRespond(withServerError());
      mockServer.expect(requestTo(INSTALLED_URI)).andRespond(withServerError());

      client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID); // failure 1
      client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID); // failure 2 → CB opens

      // Act — CB is open
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("should return empty Optional when response is malformed JSON (C-2)")
    void should_returnEmpty_when_malformedJson() {
      // Arrange
      mockServer
          .expect(requestTo(INSTALLED_URI))
          .andRespond(withSuccess("not-json{{{", MediaType.APPLICATION_JSON));

      // Act
      Optional<Boolean> result = client.fetchInstalledStatus(PLUGIN_ID, TENANT_ID);

      // Assert — parse failure → verification unavailable
      assertThat(result).isEmpty();
      mockServer.verify();
    }
  }

  @Nested
  @DisplayName("fetchInstalledStatus — input validation")
  class InputValidation {

    @Test
    @DisplayName("should throw NullPointerException for null pluginId")
    void should_throw_when_pluginIdNull() {
      assertThatThrownBy(() -> client.fetchInstalledStatus(null, TENANT_ID))
          .isInstanceOf(NullPointerException.class)
          .hasMessageContaining("pluginId must not be null");
    }

    @Test
    @DisplayName("should throw NullPointerException for null tenantId")
    void should_throw_when_tenantIdNull() {
      assertThatThrownBy(() -> client.fetchInstalledStatus(PLUGIN_ID, null))
          .isInstanceOf(NullPointerException.class)
          .hasMessageContaining("tenantId must not be null");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for invalid pluginId format (H-5)")
    void should_throw_when_pluginIdInvalid() {
      assertThatThrownBy(() -> client.fetchInstalledStatus("../../etc/passwd", TENANT_ID))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("pluginId format invalid");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for non-UUID tenantId (H-7)")
    void should_throw_when_tenantIdNotUuid() {
      assertThatThrownBy(() -> client.fetchInstalledStatus(PLUGIN_ID, "not-a-uuid"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("tenantId must be a valid UUID");
    }

    @Test
    @DisplayName("should throw IllegalArgumentException for tenantId with injection (H-7)")
    void should_throw_when_tenantIdContainsInjection() {
      assertThatThrownBy(() -> client.fetchInstalledStatus(PLUGIN_ID, "'; DROP TABLE --"))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("tenantId must be a valid UUID");
    }
  }
}
