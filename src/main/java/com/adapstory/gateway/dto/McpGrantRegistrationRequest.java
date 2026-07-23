package com.adapstory.gateway.dto;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Strict create-only registration payload sent by Agent Runtime after token exchange. */
@Schema(
    requiredProperties = "providerBindings",
    additionalProperties = Schema.AdditionalPropertiesValue.FALSE)
public record McpGrantRegistrationRequest(
    @ArraySchema(
            minItems = 1,
            maxItems = 32,
            arraySchema =
                @Schema(
                    description =
                        "Complete unique capability binding set; partial registration is rejected"))
        List<ProviderBindingGrantRequest> providerBindings,
    @Schema(description = "Immutable PDLC node authority, required for workflow capabilities")
        DelegatedCapabilityAuthorityRequest delegatedAuthority) {

  public McpGrantRegistrationRequest(List<ProviderBindingGrantRequest> providerBindings) {
    this(providerBindings, null);
  }

  public McpGrantRegistrationRequest {
    if (providerBindings == null || providerBindings.isEmpty() || providerBindings.size() > 32) {
      throw new IllegalArgumentException("providerBindings must contain 1..32 entries");
    }
    providerBindings = List.copyOf(providerBindings);
    Set<String> capabilities = new HashSet<>();
    for (ProviderBindingGrantRequest binding : providerBindings) {
      Objects.requireNonNull(binding, "providerBindings must not contain null entries");
      if (!capabilities.add(binding.capability())) {
        throw new IllegalArgumentException("providerBindings capabilities must be unique");
      }
    }
  }

  /** Rejects compatibility or misspelled fields even with Spring's permissive global mapper. */
  @JsonAnySetter
  public void rejectUnknownField(String field, Object value) {
    throw new IllegalArgumentException("unknown MCP grant registration field: " + field);
  }
}
