package com.adapstory.gateway.cache;

import com.adapstory.gateway.client.PermissionFetchClient;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

@Component
final class Bc02PluginPermissionSource implements PluginPermissionSource {

  private final PermissionFetchClient permissionFetchClient;

  Bc02PluginPermissionSource(PermissionFetchClient permissionFetchClient) {
    this.permissionFetchClient = permissionFetchClient;
  }

  @Override
  public void validatePluginId(String pluginId) {
    PermissionFetchClient.validatePluginId(pluginId);
  }

  @Override
  public Optional<List<String>> fetchPermissions(String pluginId) {
    return permissionFetchClient.fetchPermissions(pluginId);
  }
}
