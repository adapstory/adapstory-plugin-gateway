package com.adapstory.gateway.cache;

import java.util.Optional;

interface InstalledPluginStatusSource {

  Optional<Boolean> fetchInstalledStatus(String pluginId, String tenantId);
}
