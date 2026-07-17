package com.adapstory.gateway.filter;

import com.adapstory.gateway.dto.PluginSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import java.text.ParseException;
import java.util.List;

/**
 * Maps JWT claims to a {@link PluginSecurityContext}.
 *
 * <p>Extracted from {@link PluginAuthFilter} (GRASP HC-1) to isolate claim-to-DTO mapping from JWT
 * processor setup and SecurityContext management. Single responsibility: knows the mapping between
 * JWT claim keys and the plugin security context record.
 */
public final class PluginJwtClaimsMapper {

  private PluginJwtClaimsMapper() {}

  /**
   * Maps JWT claims to a {@link PluginSecurityContext}.
   *
   * @param claims validated JWT claims
   * @return plugin security context, or {@code null} if required claims are missing
   * @throws IllegalArgumentException if a plugin claim has an unexpected type
   */
  public static PluginSecurityContext mapClaims(JWTClaimsSet claims) {
    String pluginId;
    String tenantId;
    List<String> permissions;
    String trustLevel;
    try {
      pluginId = claims.getStringClaim("plugin_id");
      tenantId = claims.getStringClaim("adapstory_tenant_id");
      permissions = claims.getStringListClaim("permissions");
      trustLevel = claims.getStringClaim("trust_level");
    } catch (ParseException ex) {
      throw new IllegalArgumentException("JWT plugin claims have unexpected types", ex);
    }

    if (pluginId == null || tenantId == null || permissions == null) {
      return null;
    }

    return new PluginSecurityContext(pluginId, tenantId, List.copyOf(permissions), trustLevel);
  }
}
