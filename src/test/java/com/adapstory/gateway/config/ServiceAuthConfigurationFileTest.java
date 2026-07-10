package com.adapstory.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

@DisplayName("Service auth configuration files")
class ServiceAuthConfigurationFileTest {

  private static final String FORWARDED_BASE_URL_PROPERTY =
      "adapstory.service-auth.forwarded-base-url";
  private static final String FORWARDED_BASE_URL_ENV_PLACEHOLDER =
      "${ADAPSTORY_SERVICE_AUTH_FORWARDED_BASE_URL:}";

  @Test
  @DisplayName("application.yml maps forwarded issuer base URL from env")
  void applicationYmlMapsForwardedBaseUrl() throws IOException {
    assertForwardedBaseUrlMapped("application.yml");
  }

  @Test
  @DisplayName("application-docker.yml maps forwarded issuer base URL from env")
  void applicationDockerYmlMapsForwardedBaseUrl() throws IOException {
    assertForwardedBaseUrlMapped("application-docker.yml");
  }

  private static void assertForwardedBaseUrlMapped(String resourceName) throws IOException {
    List<PropertySource<?>> propertySources =
        new YamlPropertySourceLoader().load(resourceName, new ClassPathResource(resourceName));

    assertThat(propertySources)
        .anySatisfy(
            propertySource ->
                assertThat(propertySource.getProperty(FORWARDED_BASE_URL_PROPERTY))
                    .isEqualTo(FORWARDED_BASE_URL_ENV_PLACEHOLDER));
  }
}
