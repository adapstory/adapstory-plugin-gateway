package com.adapstory.gateway.dto;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Strict MCP grant registration JSON")
class McpGrantRegistrationRequestJsonTest {

  private final JsonMapper objectMapper =
      JsonMapper.builder()
          .findAndAddModules()
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .build();

  @Test
  @DisplayName("accepts the required canonical input-schema digest")
  void should_accept_required_input_schema_digest() {
    assertThatNoException()
        .isThrownBy(() -> objectMapper.readValue(validJson(), McpGrantRegistrationRequest.class));
  }

  @Test
  @DisplayName("rejects unknown top-level fields even when the platform mapper is permissive")
  void should_reject_unknown_registration_field() {
    assertThatThrownBy(
            () ->
                objectMapper.readValue(
                    validJson()
                        .replace(
                            "{\"providerBindings\"", "{\"legacySlugs\":[],\"providerBindings\""),
                    McpGrantRegistrationRequest.class))
        .hasRootCauseInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("rejects unknown nested binding fields rather than silently widening authority")
  void should_reject_unknown_binding_field() {
    assertThatThrownBy(
            () ->
                objectMapper.readValue(
                    validJson().replace("\"routeSlug\"", "\"legacyPlugin\":true,\"routeSlug\""),
                    McpGrantRegistrationRequest.class))
        .hasRootCauseInstanceOf(IllegalArgumentException.class);
  }

  private static String validJson() {
    return """
        {"providerBindings":[{
          "capability":"knowledge.source.search",
          "routeSlug":"ai-methodist",
          "toolName":"search_methodology_rag",
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
        """;
  }
}
