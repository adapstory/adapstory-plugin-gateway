package com.adapstory.gateway;

import com.adapstory.gateway.config.GatewayProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/** Точка входа Plugin Gateway: REST-прокси для взаимодействия плагинов с core BC. */
@SpringBootApplication(
    scanBasePackages = "com.adapstory.gateway",
    exclude = {
      com.adapstory.starter.security.config.SecurityAutoConfiguration.class,
      com.adapstory.starter.web.config.WebClientAutoConfiguration.class
    })
@EnableConfigurationProperties(GatewayProperties.class)
public class PluginGatewayApplication {

  public static void main(String[] args) {
    SpringApplication.run(PluginGatewayApplication.class, args);
  }
}
