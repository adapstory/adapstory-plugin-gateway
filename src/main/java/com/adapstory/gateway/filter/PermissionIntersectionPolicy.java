package com.adapstory.gateway.filter;

import java.util.List;
import org.springframework.stereotype.Component;

@Component
final class PermissionIntersectionPolicy {

  PermissionIntersectionResult evaluateJwtPermissions(
      List<String> jwtPermissions, String requiredPermission) {
    return jwtPermissions.contains(requiredPermission)
        ? PermissionIntersectionResult.granted()
        : PermissionIntersectionResult.jwtMissing(requiredPermission);
  }

  PermissionIntersectionResult evaluateManifestPermissions(
      String pluginId, String requiredPermission, List<String> manifestPermissions) {
    return manifestPermissions.contains(requiredPermission)
        ? PermissionIntersectionResult.granted()
        : PermissionIntersectionResult.revoked(pluginId, requiredPermission);
  }
}
