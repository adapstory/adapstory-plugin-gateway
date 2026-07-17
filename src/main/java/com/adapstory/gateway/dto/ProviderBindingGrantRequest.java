package com.adapstory.gateway.dto;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

/** Wire projection of one exact Lifecycle provider binding submitted for authorization. */
@Schema(
    requiredProperties = {
      "capability",
      "routeSlug",
      "toolName",
      "toolVersion",
      "inputSchemaVersion",
      "inputSchemaDigest",
      "authPolicy",
      "trustLevel",
      "tenantVisibility",
      "status",
      "lastValidatedAt",
      "description"
    },
    additionalProperties = Schema.AdditionalPropertiesValue.FALSE)
public record ProviderBindingGrantRequest(
    @Schema(
            description = "Canonical dotted capability selected by Agent Runtime",
            example = "knowledge.source.search",
            minLength = 3,
            maxLength = 200,
            pattern = "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$")
        String capability,
    @Schema(
            description = "Internal Plugin Gateway route slug; never model-visible",
            example = "ai-methodist",
            minLength = 1,
            maxLength = 128,
            pattern = "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
        String routeSlug,
    @Schema(
            description = "Exact MCP provider tool name declared by Lifecycle",
            example = "search_methodology_rag",
            minLength = 1,
            maxLength = 128,
            pattern = "^[a-z][a-z0-9_-]{0,127}$")
        String toolName,
    @Schema(
            description = "Provider tool contract version",
            example = "2026.07.1",
            minLength = 1,
            maxLength = 64,
            pattern = "^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
        String toolVersion,
    @Schema(
            description = "Provider input-schema version",
            example = "v1",
            minLength = 1,
            maxLength = 64,
            pattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
        String inputSchemaVersion,
    @Schema(
            description =
                "SHA-256 digest of the canonical compact sorted UTF-8 MCP inputSchema JSON; "
                    + "must exactly match Lifecycle and the live provider contract",
            example = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            pattern = "^sha256:[0-9a-f]{64}$")
        String inputSchemaDigest,
    @Schema(
            description = "Only supported provider authentication policy",
            allowableValues = "tenant-service-jwt")
        String authPolicy,
    @Schema(
            description = "Lifecycle-assigned provider trust tier",
            allowableValues = {"CORE", "VERIFIED", "COMMUNITY"})
        String trustLevel,
    @Schema(description = "Provider data visibility boundary", allowableValues = "tenant")
        String tenantVisibility,
    @Schema(description = "Only callable provider state", allowableValues = "available")
        String status,
    @Schema(description = "Lifecycle validation instant used for stale-binding detection")
        Instant lastValidatedAt,
    @Schema(
            description =
                "Exact reviewed tool description; must match Lifecycle and live MCP metadata",
            minLength = 20,
            maxLength = 4096,
            pattern = "^[^\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]*$")
        String description) {

  /** Rejects compatibility or misspelled binding fields before authority is derived. */
  @JsonAnySetter
  public void rejectUnknownField(String field, Object value) {
    throw new IllegalArgumentException("unknown provider binding field: " + field);
  }
}
