package com.adapstory.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.filter.ShallowEtagHeaderFilter;

@SpringBootTest
@ActiveProfiles("test")
@DisplayName("Plugin Gateway caching integration")
class GatewayCachingIntegrationTest {

  @Autowired private WebApplicationContext webApplicationContext;

  @Test
  @DisplayName("disables shallow ETag filtering for dynamic plugin gateway responses")
  void disablesShallowEtagFilteringForDynamicPluginGatewayResponses() {
    assertThat(webApplicationContext.getBeansOfType(ShallowEtagHeaderFilter.class)).isEmpty();
  }
}
