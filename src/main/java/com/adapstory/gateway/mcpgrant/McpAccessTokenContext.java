package com.adapstory.gateway.mcpgrant;

import java.time.Instant;
import java.util.Objects;

/** Security-relevant claims from one validated, Gateway-audience access token. */
public record McpAccessTokenContext(
    String tokenId, String subject, String tenantId, String authorizedParty, Instant expiresAt) {

  private static final int MAX_CONTEXT_LENGTH = 512;

  public McpAccessTokenContext {
    tokenId = requireContextValue(tokenId, "tokenId");
    subject = requireContextValue(subject, "subject");
    tenantId = requireContextValue(tenantId, "tenantId");
    authorizedParty = requireContextValue(authorizedParty, "authorizedParty");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
  }

  private static String requireContextValue(String value, String field) {
    if (value == null
        || value.isBlank()
        || value.length() > MAX_CONTEXT_LENGTH
        || value
            .chars()
            .anyMatch(
                character ->
                    Character.isWhitespace(character) || Character.isISOControl(character))) {
      throw new IllegalArgumentException(field + " is not canonical");
    }
    return value;
  }
}
