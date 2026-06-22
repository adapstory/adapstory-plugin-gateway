package com.adapstory.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

class DevProfileConfigurationTest {

  @Test
  void shouldPointBc02ClientsAtPluginLifecycleServicePort() throws IOException {
    PropertySource<?> devProfile =
        new YamlPropertySourceLoader()
            .load("application-dev", new ClassPathResource("application-dev.yml"))
            .getFirst();

    assertThat(devProfile.getProperty("gateway.bc02.base-url"))
        .isEqualTo("http://dev-plugin-lifecycle-svc.env-dev.svc.cluster.local:8083");
    assertThat(devProfile.getProperty("gateway.routes.plugin"))
        .isEqualTo("http://dev-plugin-lifecycle-svc.env-dev.svc.cluster.local:8083");
  }
}
