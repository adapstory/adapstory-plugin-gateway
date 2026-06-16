package com.adapstory.gateway.filter;

import com.adapstory.gateway.cache.PermissionCacheService;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Component;

@Component
final class PluginManifestPermissionResolver {

  private final PermissionCacheService permissionCacheService;

  PluginManifestPermissionResolver(PermissionCacheService permissionCacheService) {
    this.permissionCacheService =
        Objects.requireNonNull(permissionCacheService, "permissionCacheService must not be null");
  }

  Optional<List<String>> resolveManifestPermissions(String pluginId) {
    return permissionCacheService
        .getCachedPermissions(pluginId)
        .or(() -> permissionCacheService.fetchAndCachePermissions(pluginId));
  }
}
