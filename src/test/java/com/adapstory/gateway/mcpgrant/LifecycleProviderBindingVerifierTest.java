package com.adapstory.gateway.mcpgrant;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

@DisplayName("Plugin Lifecycle provider-binding verifier")
class LifecycleProviderBindingVerifierTest {

  private MockRestServiceServer server;
  private LifecycleProviderBindingVerifier verifier;

  @BeforeEach
  void setUp() {
    RestClient.Builder builder = RestClient.builder().baseUrl("http://plugin-lifecycle:8080");
    server = MockRestServiceServer.bindTo(builder).build();
    verifier = new LifecycleProviderBindingVerifier(builder.build());
  }

  @Test
  @DisplayName("sends all canonical bindings in one tenant-scoped verification request")
  void should_verify_complete_binding_set_in_one_call() {
    server
        .expect(
            requestTo("http://plugin-lifecycle:8080/api/bc-02/plugin-lifecycle/v1/tools/verify"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header("X-Tenant-Id", "tenant-123"))
        .andExpect(header("X-User-Id", "actor-456"))
        .andExpect(
            header("X-Request-Id", org.hamcrest.Matchers.not(org.hamcrest.Matchers.blankString())))
        .andExpect(
            content()
                .json(
                    """
                    {"providerBindings":[{
                      "pluginSlug":"ai-methodist",
                      "toolName":"search_methodology_rag",
                      "capability":"knowledge.source.search",
                      "toolVersion":"2026.07.1",
                      "inputSchemaVersion":"v1",
                      "inputSchemaDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                      "authPolicy":"tenant-service-jwt",
                      "trustLevel":"CORE",
                      "tenantVisibility":"tenant",
                      "status":"available",
                      "lastValidatedAt":"2026-07-16T12:00:00Z",
                      "description":"Search the tenant methodology knowledge base. Use only for grounded sources."
                    }]}
                    """,
                    true))
        .andRespond(withStatus(HttpStatus.NO_CONTENT));

    assertThatCode(() -> verifier.verify("tenant-123", "actor-456", List.of(binding())))
        .doesNotThrowAnyException();
    server.verify();
  }

  @Test
  @DisplayName("maps Lifecycle ambiguity, drift, and unavailability to typed fail-closed reasons")
  void should_map_typed_lifecycle_failures() {
    expectStatus(HttpStatus.CONFLICT);
    assertThatThrownBy(() -> verifier.verify("tenant-123", "actor-456", List.of(binding())))
        .isInstanceOfSatisfying(
            ProviderBindingVerificationException.class,
            error ->
                org.assertj.core.api.Assertions.assertThat(error.reason())
                    .isEqualTo(ProviderBindingVerificationException.Reason.CONFLICT));
    server.verify();

    RestClient.Builder invalidBuilder =
        RestClient.builder().baseUrl("http://plugin-lifecycle:8080");
    server = MockRestServiceServer.bindTo(invalidBuilder).build();
    verifier = new LifecycleProviderBindingVerifier(invalidBuilder.build());
    expectStatus(HttpStatus.UNPROCESSABLE_ENTITY);
    assertThatThrownBy(() -> verifier.verify("tenant-123", "actor-456", List.of(binding())))
        .isInstanceOfSatisfying(
            ProviderBindingVerificationException.class,
            error ->
                org.assertj.core.api.Assertions.assertThat(error.reason())
                    .isEqualTo(ProviderBindingVerificationException.Reason.INVALID));

    RestClient.Builder unavailableBuilder =
        RestClient.builder().baseUrl("http://plugin-lifecycle:8080");
    server = MockRestServiceServer.bindTo(unavailableBuilder).build();
    verifier = new LifecycleProviderBindingVerifier(unavailableBuilder.build());
    expectStatus(HttpStatus.SERVICE_UNAVAILABLE);
    assertThatThrownBy(() -> verifier.verify("tenant-123", "actor-456", List.of(binding())))
        .isInstanceOfSatisfying(
            ProviderBindingVerificationException.class,
            error ->
                org.assertj.core.api.Assertions.assertThat(error.reason())
                    .isEqualTo(ProviderBindingVerificationException.Reason.UNAVAILABLE));
  }

  private void expectStatus(HttpStatus status) {
    server
        .expect(
            requestTo("http://plugin-lifecycle:8080/api/bc-02/plugin-lifecycle/v1/tools/verify"))
        .andExpect(method(HttpMethod.POST))
        .andRespond(withStatus(status).contentType(MediaType.APPLICATION_JSON).body("{}"));
  }

  private static ProviderBindingGrant binding() {
    return new ProviderBindingGrant(
        "knowledge.source.search",
        "ai-methodist",
        "search_methodology_rag",
        "2026.07.1",
        "v1",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "tenant-service-jwt",
        "CORE",
        "tenant",
        "available",
        Instant.parse("2026-07-16T12:00:00Z"),
        "Search the tenant methodology knowledge base. Use only for grounded sources.");
  }
}
