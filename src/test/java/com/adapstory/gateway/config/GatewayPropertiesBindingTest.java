package com.adapstory.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

@DisplayName("GatewayProperties binding")
class GatewayPropertiesBindingTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withUserConfiguration(PropertiesConfig.class)
          .withPropertyValues(
              "gateway.jwt.jwks-uri=http://localhost/certs",
              "gateway.jwt.issuer=test-issuer",
              "gateway.jwt.audience=test-audience",
              "gateway.jwt.jwks-cache-ttl-minutes=5",
              "gateway.bc02.base-url=http://localhost:8081",
              "gateway.permission-cache.ttl-minutes=5",
              "gateway.permission-cache.key-prefix=plugin:permissions:",
              "gateway.installed-cache.ttl-minutes=5",
              "gateway.installed-cache.negative-ttl-seconds=30",
              "gateway.webhook.retry-max-attempts=3",
              "gateway.webhook.retry-initial-interval-ms=1000",
              "gateway.webhook.retry-multiplier=2.0",
              "gateway.webhook.plugin-pod-port=8000");

  @Test
  @DisplayName("binds a non-null MCP config when the mcp section is omitted")
  void bindsDefaultMcpConfigWhenSectionIsOmitted() {
    contextRunner.run(
        context -> {
          assertThat(context).hasNotFailed();
          GatewayProperties properties = context.getBean(GatewayProperties.class);

          assertThat(properties.mcp()).isNotNull();
          assertThat(properties.mcp().pluginPodPort()).isEqualTo(8000);
          assertThat(properties.mcp().pluginHostTemplate())
              .isEqualTo("plugin-%s.plugins.svc.cluster.local");
          assertThat(properties.mcp().connectTimeoutMs()).isEqualTo(30000);
          assertThat(properties.mcp().pluginRoutes()).isEmpty();
        });
  }

  @Test
  @DisplayName("binds browser route slug to canonical plugin id aliases")
  void bindsPluginIdAliases() {
    contextRunner
        .withPropertyValues(
            "gateway.plugin-id-aliases.ai-course-generator=adapstory.ai.course-generator")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              GatewayProperties properties = context.getBean(GatewayProperties.class);

              assertThat(properties.pluginIdAliases())
                  .containsEntry("ai-course-generator", "adapstory.ai.course-generator");
            });
  }

  @Test
  @DisplayName("binds configured MCP plugin routes with scalar defaults")
  void bindsMcpPluginRoutesWithDefaults() {
    contextRunner
        .withPropertyValues(
            "gateway.mcp.plugin-pod-port=8000",
            "gateway.mcp.plugin-host-template=plugin-%s.plugins.svc.cluster.local",
            "gateway.mcp.connect-timeout-ms=30000",
            "gateway.mcp.plugin-routes[0].slug=dify-plugin",
            "gateway.mcp.plugin-routes[0].base-url=http://dev-dify-plugin-svc.env-dev.svc.cluster.local:8000")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              GatewayProperties.McpConfig mcp = context.getBean(GatewayProperties.class).mcp();

              assertThat(mcp.pluginPodPort()).isEqualTo(8000);
              assertThat(mcp.connectTimeoutMs()).isEqualTo(30000);
              assertThat(mcp.pluginRoutes())
                  .containsExactly(
                      new GatewayProperties.PluginRoute(
                          "dify-plugin",
                          "http://dev-dify-plugin-svc.env-dev.svc.cluster.local:8000"));
            });
  }

  @EnableConfigurationProperties(GatewayProperties.class)
  static class PropertiesConfig {}
}
