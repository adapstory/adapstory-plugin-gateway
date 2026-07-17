package com.adapstory.gateway.routing;

import com.adapstory.gateway.util.McpHttpHeaders;
import com.adapstory.gateway.util.PluginSlugValidator;

/** Tenant- and provider-scoped key for one stateful MCP server session. */
record McpSessionAffinityKey(String tenantId, String routeSlug, String sessionId) {

  private static final int MAX_TENANT_ID_LENGTH = 512;

  McpSessionAffinityKey {
    if (tenantId == null
        || tenantId.isBlank()
        || tenantId.length() > MAX_TENANT_ID_LENGTH
        || tenantId.chars().anyMatch(Character::isWhitespace)
        || !PluginSlugValidator.isValidSlug(routeSlug)
        || !McpHttpHeaders.isCanonicalSessionId(sessionId)) {
      throw new IllegalArgumentException("MCP session affinity key is not canonical");
    }
  }
}
