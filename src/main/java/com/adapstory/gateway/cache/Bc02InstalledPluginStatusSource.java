package com.adapstory.gateway.cache;

import com.adapstory.gateway.client.InstalledPluginFetchClient;
import java.util.Optional;
import org.springframework.stereotype.Component;

@Component
final class Bc02InstalledPluginStatusSource implements InstalledPluginStatusSource {

  private final InstalledPluginFetchClient fetchClient;

  Bc02InstalledPluginStatusSource(InstalledPluginFetchClient fetchClient) {
    this.fetchClient = fetchClient;
  }

  @Override
  public Optional<Boolean> fetchInstalledStatus(String pluginId, String tenantId) {
    return fetchClient.fetchInstalledStatus(pluginId, tenantId);
  }
}
