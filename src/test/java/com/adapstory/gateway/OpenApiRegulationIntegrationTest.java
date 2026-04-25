package com.adapstory.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Runtime integration tests for the generated Plugin Gateway OpenAPI contract.
 *
 * <p>Verifies CalVer metadata, explicit compatibility-major, and boolean {@code x-AI-ready=true} on
 * documented gateway routes.
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("Plugin Gateway OpenAPI regulation integration")
class OpenApiRegulationIntegrationTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  @Autowired private WebApplicationContext webApplicationContext;

  private MockMvc mockMvc;

  @BeforeEach
  void setUpMockMvc() {
    mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
  }

  @Test
  @DisplayName("generated OpenAPI spec should expose CalVer and compatibility-major metadata")
  void shouldExposeCalverAndCompatibilityMajor() throws Exception {
    String body = fetchApiDocs();
    JsonNode root = MAPPER.readTree(body);
    JsonNode info = root.get("info");

    assertThat(info).isNotNull();
    assertThat(info.get("version").asText()).isEqualTo("2026.04.1");
    assertThat(info.get("x-adapstory-api-major").asText()).isEqualTo("v1");
    assertThat(info.get("x-adapstory-api-audience").asText()).isEqualTo("internal");
    assertThat(info.get("x-adapstory-ai-ready").asBoolean()).isTrue();
    assertThat(root.get("paths").has("/internal/plugins/v1/{slug}/mcp")).isTrue();
    assertThat(root.get("paths").has("/internal/plugins/{slug}/mcp")).isFalse();
  }

  @Test
  @DisplayName("generated OpenAPI spec should expose boolean x-AI-ready on every operation")
  void shouldExposeBooleanXAiReadyOnOperations() throws Exception {
    String body = fetchApiDocs();
    JsonNode paths = MAPPER.readTree(body).get("paths");
    assertThat(paths).isNotNull();

    Iterator<Map.Entry<String, JsonNode>> pathEntries = paths.fields();
    while (pathEntries.hasNext()) {
      Map.Entry<String, JsonNode> pathEntry = pathEntries.next();
      Iterator<Map.Entry<String, JsonNode>> methods = pathEntry.getValue().fields();
      while (methods.hasNext()) {
        Map.Entry<String, JsonNode> methodEntry = methods.next();
        JsonNode operation = methodEntry.getValue();
        if (!operation.has("operationId")) {
          continue;
        }
        assertThat(operation.has("x-AI-ready")).isTrue();
        assertThat(operation.get("x-AI-ready").isBoolean()).isTrue();
        assertThat(operation.get("x-AI-ready").asBoolean()).isTrue();
      }
    }
  }

  @Test
  @DisplayName("optionally exports raw OpenAPI JSON when openapi.exportDir is set")
  void shouldExportWhenRequested() throws Exception {
    String exportDir = System.getProperty("openapi.exportDir");
    if (exportDir == null || exportDir.isBlank()) {
      return;
    }

    String body = fetchApiDocs();
    Path outputDir = Path.of(exportDir);
    Files.createDirectories(outputDir);
    Files.writeString(outputDir.resolve("openapi.json"), body);
    assertThat(Files.exists(outputDir.resolve("openapi.json"))).isTrue();
  }

  private String fetchApiDocs() throws Exception {
    return mockMvc
        .perform(get("/v3/api-docs"))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString();
  }
}
