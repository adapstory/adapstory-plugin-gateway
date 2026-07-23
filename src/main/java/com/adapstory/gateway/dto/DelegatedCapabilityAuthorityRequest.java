package com.adapstory.gateway.dto;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/** Strict wire contract for one immutable PDLC node capability grant. */
@Schema(additionalProperties = Schema.AdditionalPropertiesValue.FALSE)
public record DelegatedCapabilityAuthorityRequest(
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED) String runId,
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED) String nodeId,
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED) String grantId,
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED) String policyVersion,
    @ArraySchema(minItems = 1, maxItems = 32) List<String> capabilities) {

  /** Reject compatibility or misspelled authority fields. */
  @JsonAnySetter
  public void rejectUnknownField(String field, Object value) {
    throw new IllegalArgumentException("unknown delegated authority field: " + field);
  }
}
