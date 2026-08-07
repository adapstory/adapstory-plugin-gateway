package com.adapstory.gateway.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Owns explicit schemas for Spring MVC transport types that are not domain DTOs. */
@Configuration
public class OpenApiSchemaConfig {

  /** Describes the framework streaming callback as its actual wire-level SSE string. */
  @Bean
  public OpenApiCustomizer streamingResponseBodySchemaCustomizer() {
    return openApi -> {
      Components components = openApi.getComponents();
      if (components == null) {
        components = new Components();
        openApi.setComponents(components);
      }
      Schema<?> streaming =
          components.getSchemas() == null
              ? null
              : components.getSchemas().get("StreamingResponseBody");
      if (streaming == null) {
        streaming = new StringSchema();
        components.addSchemas("StreamingResponseBody", streaming);
      }
      streaming.setType("string");
      streaming.setDescription("Server-sent event stream written directly to the HTTP response");
    };
  }
}
