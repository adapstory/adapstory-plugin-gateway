package com.adapstory.gateway.cache;

import java.util.List;
import java.util.Optional;

interface PluginPermissionSource {

  void validatePluginId(String pluginId);

  Optional<List<String>> fetchPermissions(String pluginId);
}
