package com.adapstory.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.adapstory.gateway.filter.McpGrantJwtAuthenticationFilter;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.adapstory.gateway.filter.PluginMcpJwtClaimFilter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Filter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.web.FilterChainProxy;
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

  @Autowired private FilterChainProxy springSecurityFilterChain;

  private MockMvc mockMvc;

  @BeforeEach
  void setUpMockMvc() {
    mockMvc =
        MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
  }

  @Test
  @DisplayName("generated OpenAPI spec should expose CalVer and compatibility-major metadata")
  void shouldExposeCalverAndCompatibilityMajor() throws Exception {
    String body = fetchApiDocs();
    JsonNode root = MAPPER.readTree(body);
    JsonNode info = root.get("info");

    assertThat(info).isNotNull();
    assertThat(info.get("version").textValue()).isEqualTo("2026.07.1");
    assertThat(info.get("x-adapstory-api-major").textValue()).isEqualTo("v1");
    assertThat(info.get("x-adapstory-api-audience").textValue()).isEqualTo("internal");
    assertThat(info.get("x-adapstory-ai-ready").asBoolean()).isTrue();
    assertThat(root.get("paths").has("/internal/plugins/v1/{slug}/mcp")).isTrue();
    assertThat(root.get("paths").has("/internal/mcp-grants/v1")).isTrue();
    assertThat(root.get("paths").has("/internal/plugins/{slug}/mcp")).isFalse();

    JsonNode schemas = root.path("components").path("schemas");
    JsonNode registration = schemas.path("McpGrantRegistrationRequest");
    assertThat(registration.path("additionalProperties").asBoolean()).isFalse();
    assertThat(registration.path("required").size()).isEqualTo(1);
    assertThat(registration.path("required").get(0).textValue()).isEqualTo("providerBindings");
    JsonNode bindings = registration.path("properties").path("providerBindings");
    assertThat(bindings.path("minItems").intValue()).isEqualTo(1);
    assertThat(bindings.path("maxItems").intValue()).isEqualTo(32);

    JsonNode binding = schemas.path("ProviderBindingGrantRequest");
    assertThat(binding.path("additionalProperties").asBoolean()).isFalse();
    assertThat(binding.path("required").size()).isEqualTo(12);
    assertThat(binding.path("properties").path("capability").path("pattern").textValue())
        .isNotBlank();
    assertThat(binding.path("properties").path("inputSchemaDigest").path("pattern").textValue())
        .isEqualTo("^sha256:[0-9a-f]{64}$");
    assertThat(binding.path("properties").path("description").path("maxLength").intValue())
        .isEqualTo(4096);
    assertThat(binding.path("properties").path("description").path("minLength").intValue())
        .isEqualTo(20);

    JsonNode streamingResponseBody = schemas.path("StreamingResponseBody");
    assertThat(streamingResponseBody.path("type").textValue()).isEqualTo("string");
    assertThat(streamingResponseBody.path("description").textValue()).isNotBlank();

    JsonNode grantOperation = root.path("paths").path("/internal/mcp-grants/v1").path("post");
    assertThat(grantOperation.path("security").get(0).has("mcpGatewayBearer")).isTrue();
    assertThat(root.path("components").path("securitySchemes").has("mcpGatewayBearer")).isTrue();
    var parameterNames =
        java.util.stream.StreamSupport.stream(
                grantOperation.path("parameters").spliterator(), false)
            .map(parameter -> parameter.path("name").textValue())
            .collect(java.util.stream.Collectors.toSet());
    assertThat(parameterNames).contains("X-Tenant-Id", "X-User-Id", "X-Adapstory-User-Id");
  }

  @Test
  @DisplayName("generated OpenAPI spec should expose boolean x-AI-ready on every operation")
  void shouldExposeBooleanXAiReadyOnOperations() throws Exception {
    String body = fetchApiDocs();
    JsonNode paths = MAPPER.readTree(body).get("paths");
    assertThat(paths).isNotNull();

    Iterator<Map.Entry<String, JsonNode>> pathEntries = paths.properties().iterator();
    while (pathEntries.hasNext()) {
      Map.Entry<String, JsonNode> pathEntry = pathEntries.next();
      Iterator<Map.Entry<String, JsonNode>> methods = pathEntry.getValue().properties().iterator();
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
  @DisplayName("capability grant security should own only the canonical MCP surfaces")
  void shouldApplyCapabilityGrantSecurityOnlyToCanonicalRoutes() {
    List<Filter> canonicalFilters =
        springSecurityFilterChain.getFilters("/internal/plugins/v1/course-builder/mcp");
    List<Filter> registrationFilters =
        springSecurityFilterChain.getFilters("/internal/mcp-grants/v1");
    List<Filter> removedRouteFilters =
        springSecurityFilterChain.getFilters("/internal/plugins/course-builder/mcp");

    assertThat(canonicalFilters)
        .anyMatch(McpGrantJwtAuthenticationFilter.class::isInstance)
        .noneMatch(PluginAuthFilter.class::isInstance);
    assertThat(canonicalFilters).anyMatch(PluginMcpJwtClaimFilter.class::isInstance);
    assertThat(registrationFilters)
        .anyMatch(McpGrantJwtAuthenticationFilter.class::isInstance)
        .noneMatch(PluginAuthFilter.class::isInstance);
    assertThat(removedRouteFilters).noneMatch(PluginMcpJwtClaimFilter.class::isInstance);
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
    // JSON is a valid YAML 1.2 document; keep both regulated artifacts byte-identical.
    Files.writeString(outputDir.resolve("openapi.yaml"), body);
    assertThat(Files.exists(outputDir.resolve("openapi.json"))).isTrue();
    assertThat(Files.exists(outputDir.resolve("openapi.yaml"))).isTrue();
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
