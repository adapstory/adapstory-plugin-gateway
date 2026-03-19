package com.adapstory.gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Обеспечивает Jackson 2 ObjectMapper для компонентов Plugin Gateway.
 *
 * <p>Plugin Gateway использует Jackson 2 (com.fasterxml.jackson.databind). Spring Boot 4
 * автоконфигурирует только Jackson 3 (tools.jackson.databind), поэтому необходим явный бин.
 *
 * <p>Tech debt: migrate to Jackson 3 (tools.jackson.databind.ObjectMapper) for consistency with
 * adapstory-shared-libs. Track as part of Jackson 3 migration epic across all BCs.
 */
@Configuration
class JacksonConfig {

  @Bean
  ObjectMapper objectMapper() {
    return JsonMapper.builder().findAndAddModules().build();
  }
}
