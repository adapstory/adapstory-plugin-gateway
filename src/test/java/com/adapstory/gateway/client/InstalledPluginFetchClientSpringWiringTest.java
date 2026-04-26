package com.adapstory.gateway.client;

import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.config.GatewayProperties.Bc02Config;
import com.adapstory.gateway.config.GatewayProperties.InstalledCacheConfig;
import com.adapstory.gateway.config.GatewayProperties.JwtConfig;
import com.adapstory.gateway.config.GatewayProperties.McpConfig;
import com.adapstory.gateway.config.GatewayProperties.PermissionCacheConfig;
import com.adapstory.gateway.config.GatewayProperties.PermissionsConfig;
import com.adapstory.gateway.config.GatewayProperties.WebhookConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

@DisplayName("InstalledPluginFetchClient — Spring wiring")
class InstalledPluginFetchClientSpringWiringTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withBean(GatewayProperties.class, InstalledPluginFetchClientSpringWiringTest::properties)
          .withBean(RestClient.Builder.class, RestClient::builder)
          .withBean(CircuitBreakerRegistry.class, CircuitBreakerRegistry::ofDefaults)
          .withBean(ObjectMapper.class, ObjectMapper::new)
          .withBean(InstalledPluginFetchClient.class);

  @Test
  @DisplayName("Spring creates the component with its production constructor")
  void springCreatesComponentWithProductionConstructor() {
    contextRunner.run(
        context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).hasSingleBean(InstalledPluginFetchClient.class);
        });
  }

  private static GatewayProperties properties() {
    return new GatewayProperties(
        new JwtConfig("http://keycloak/realms/adapstory/certs", "issuer", "audience", 5),
        Map.of(),
        new PermissionsConfig(Map.of()),
        new PermissionCacheConfig(5, "plugin-gateway:permissions:"),
        new InstalledCacheConfig(5, 30),
        new WebhookConfig(3, 100, 2.0, 8000, "plugin-%s", "secret"),
        new Bc02Config("http://plugin-lifecycle:8080"),
        new McpConfig(8000, "plugin-%s", 3000));
  }
}
