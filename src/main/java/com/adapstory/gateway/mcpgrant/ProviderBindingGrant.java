package com.adapstory.gateway.mcpgrant;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Exact capability-to-provider binding authorized for one short-lived Gateway grant. */
public record ProviderBindingGrant(
    String capability,
    String routeSlug,
    String toolName,
    String toolVersion,
    String inputSchemaVersion,
    String inputSchemaDigest,
    String authPolicy,
    String trustLevel,
    String tenantVisibility,
    String status,
    Instant lastValidatedAt,
    String description) {

  private static final int MAX_CAPABILITY_LENGTH = 200;
  private static final int MAX_METADATA_LENGTH = 64;
  private static final Pattern CAPABILITY_PATTERN =
      Pattern.compile("^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$");
  private static final Pattern ROUTE_SLUG_PATTERN =
      Pattern.compile("^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$");
  private static final Pattern TOOL_NAME_PATTERN = Pattern.compile("^[a-z][a-z0-9_-]{0,127}$");
  private static final Pattern TOOL_VERSION_PATTERN =
      Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$");
  private static final Pattern INPUT_SCHEMA_VERSION_PATTERN =
      Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$");
  private static final Pattern INPUT_SCHEMA_DIGEST_PATTERN =
      Pattern.compile("^sha256:[0-9a-f]{64}$");
  private static final Set<String> TRUST_LEVELS = Set.of("CORE", "VERIFIED", "COMMUNITY");

  public ProviderBindingGrant {
    capability =
        requirePattern(capability, "capability", CAPABILITY_PATTERN, MAX_CAPABILITY_LENGTH);
    routeSlug = requirePattern(routeSlug, "routeSlug", ROUTE_SLUG_PATTERN, 128);
    toolName = requirePattern(toolName, "toolName", TOOL_NAME_PATTERN, 128);
    toolVersion =
        requirePattern(toolVersion, "toolVersion", TOOL_VERSION_PATTERN, MAX_METADATA_LENGTH);
    inputSchemaVersion =
        requirePattern(
            inputSchemaVersion,
            "inputSchemaVersion",
            INPUT_SCHEMA_VERSION_PATTERN,
            MAX_METADATA_LENGTH);
    inputSchemaDigest =
        requirePattern(inputSchemaDigest, "inputSchemaDigest", INPUT_SCHEMA_DIGEST_PATTERN, 71);
    if (!"tenant-service-jwt".equals(authPolicy)) {
      throw new IllegalArgumentException("authPolicy must be tenant-service-jwt");
    }
    if (!TRUST_LEVELS.contains(trustLevel)) {
      throw new IllegalArgumentException("trustLevel is not canonical");
    }
    if (!"tenant".equals(tenantVisibility)) {
      throw new IllegalArgumentException("tenantVisibility must be tenant");
    }
    if (!"available".equals(status)) {
      throw new IllegalArgumentException("status must be available");
    }
    Objects.requireNonNull(lastValidatedAt, "lastValidatedAt must not be null");
    if (description == null
        || description.isBlank()
        || description.length() < 20
        || description.length() > 4096
        || description.chars().anyMatch(ProviderBindingGrant::isForbiddenControl)) {
      throw new IllegalArgumentException("description is not canonical");
    }
  }

  private static boolean isForbiddenControl(int character) {
    return Character.isISOControl(character)
        && character != '\n'
        && character != '\r'
        && character != '\t';
  }

  private static String requirePattern(String value, String field, Pattern pattern, int maxLength) {
    if (value == null
        || value.isBlank()
        || value.length() > maxLength
        || !pattern.matcher(value).matches()) {
      throw new IllegalArgumentException(field + " is not canonical");
    }
    return value;
  }
}
