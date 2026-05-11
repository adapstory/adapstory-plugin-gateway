package com.adapstory.gateway.filter;

import com.adapstory.gateway.dto.PluginSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
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
   */
  public static PluginSecurityContext mapClaims(JWTClaimsSet claims) {
    String pluginId = claims.getStringClaim("plugin_id");
    String tenantId = claims.getStringClaim("adapstory_tenant_id");
    List<String> permissions = claims.getStringListClaim("permissions");
    String trustLevel = claims.getStringClaim("trust_level");

    if (pluginId == null || tenantId == null || permissions == null) {
      return null;
    }

    return new PluginSecurityContext(pluginId, tenantId, List.copyOf(permissions), trustLevel);
  }
}
