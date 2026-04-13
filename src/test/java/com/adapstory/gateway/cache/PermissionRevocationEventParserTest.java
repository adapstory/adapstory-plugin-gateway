package com.adapstory.gateway.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

@DisplayName("PermissionRevocationEventParser")
class PermissionRevocationEventParserTest {

  private PermissionRevocationEventParser eventParser;
  private StringRedisTemplate redisTemplate;
  private ValueOperations<String, String> valueOperations;
  private ObjectMapper objectMapper;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    redisTemplate = mock(StringRedisTemplate.class);
    valueOperations = mock(ValueOperations.class);
    when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    objectMapper = new ObjectMapper();

    eventParser = new PermissionRevocationEventParser(redisTemplate, objectMapper);
  }

  @Nested
  @DisplayName("parseEvent")
  class ParseEvent {

    @Test
    @DisplayName("Valid JSON returns parsed JsonNode tree")
    void validJson_returnsTree() throws JsonProcessingException {
      // Arrange
      String json = "{\"specversion\":\"1.0\",\"id\":\"ce-123\",\"data\":{}}";

      // Act
      JsonNode tree = eventParser.parseEvent(json);

      // Assert
      assertThat(tree.path("specversion").asText()).isEqualTo("1.0");
      assertThat(tree.path("id").asText()).isEqualTo("ce-123");
    }

    @Test
    @DisplayName("Invalid JSON throws JsonProcessingException")
    void invalidJson_throwsException() {
      // Act & Assert
      assertThatThrownBy(() -> eventParser.parseEvent("not-valid-json{{{"))
          .isInstanceOf(JsonProcessingException.class);
    }
  }

  @Nested
  @DisplayName("extractCeId")
  class ExtractCeId {

    @Test
    @DisplayName("Returns ce-id when present")
    void presentId_returnsValue() throws JsonProcessingException {
      // Arrange
      JsonNode tree = objectMapper.readTree("{\"id\":\"ce-uuid-123\"}");

      // Act
      String ceId = eventParser.extractCeId(tree);

      // Assert
      assertThat(ceId).isEqualTo("ce-uuid-123");
    }

    @Test
    @DisplayName("Returns null when id field is missing")
    void missingId_returnsNull() throws JsonProcessingException {
      // Arrange
      JsonNode tree = objectMapper.readTree("{\"specversion\":\"1.0\"}");

      // Act
      String ceId = eventParser.extractCeId(tree);

      // Assert
      assertThat(ceId).isNull();
    }

    @Test
    @DisplayName("Returns null when id field is null")
    void nullId_returnsNull() throws JsonProcessingException {
      // Arrange
      JsonNode tree = objectMapper.readTree("{\"id\":null}");

      // Act
      String ceId = eventParser.extractCeId(tree);

      // Assert
      assertThat(ceId).isNull();
    }
  }

  @Nested
  @DisplayName("isDuplicateEvent")
  class IsDuplicateEvent {

    @Test
    @DisplayName("First event (setIfAbsent returns true) is not a duplicate")
    void firstEvent_isNotDuplicate() {
      // Arrange
      when(valueOperations.setIfAbsent(
              eq("revoked-event-processed:ce-123"), eq("1"), eq(Duration.ofHours(24))))
          .thenReturn(true);

      // Act
      boolean duplicate = eventParser.isDuplicateEvent("ce-123");

      // Assert
      assertThat(duplicate).isFalse();
      verify(valueOperations)
          .setIfAbsent(eq("revoked-event-processed:ce-123"), eq("1"), eq(Duration.ofHours(24)));
    }

    @Test
    @DisplayName("Already-processed event (setIfAbsent returns false) is a duplicate")
    void alreadyProcessed_isDuplicate() {
      // Arrange — key already exists
      when(valueOperations.setIfAbsent(
              eq("revoked-event-processed:ce-123"), eq("1"), eq(Duration.ofHours(24))))
          .thenReturn(false);

      // Act
      boolean duplicate = eventParser.isDuplicateEvent("ce-123");

      // Assert
      assertThat(duplicate).isTrue();
    }
  }

  @Nested
  @DisplayName("validatePayload")
  class ValidatePayload {

    @Test
    @DisplayName("Valid payload with reasonable permissions returns true")
    void validPayload_returnsTrue() throws JsonProcessingException {
      // Arrange
      JsonNode dataNode =
          objectMapper.readTree(
              "{\"pluginId\":\"test-plugin\",\"revokedPermissions\":[\"read:scope\",\"write:other\"]}");

      // Act
      boolean valid = eventParser.validatePayload(dataNode);

      // Assert
      assertThat(valid).isTrue();
    }

    @Test
    @DisplayName("Rejects oversized payload with >100 permissions")
    void rejectsOversizedPayload() throws JsonProcessingException {
      // Arrange
      String permissions =
          IntStream.range(0, 101)
              .mapToObj(i -> "\"read:scope_" + i + "\"")
              .collect(Collectors.joining(",", "[", "]"));
      JsonNode dataNode =
          objectMapper.readTree(
              "{\"pluginId\":\"test-plugin\",\"revokedPermissions\":" + permissions + "}");

      // Act
      boolean valid = eventParser.validatePayload(dataNode);

      // Assert
      assertThat(valid).isFalse();
    }

    @Test
    @DisplayName("Rejects scope exceeding max length (255 chars)")
    void rejectsScopeExceedingMaxLength() throws JsonProcessingException {
      // Arrange
      String longScope = "x".repeat(256);
      JsonNode dataNode =
          objectMapper.readTree(
              "{\"pluginId\":\"test-plugin\",\"revokedPermissions\":[\"" + longScope + "\"]}");

      // Act
      boolean valid = eventParser.validatePayload(dataNode);

      // Assert
      assertThat(valid).isFalse();
    }

    @Test
    @DisplayName("Returns true when revokedPermissions is missing")
    void missingRevokedPermissions_returnsTrue() throws JsonProcessingException {
      // Arrange
      JsonNode dataNode = objectMapper.readTree("{\"pluginId\":\"test-plugin\"}");

      // Act
      boolean valid = eventParser.validatePayload(dataNode);

      // Assert
      assertThat(valid).isTrue();
    }

    @Test
    @DisplayName("Accepts payload with exactly 100 permissions (at limit)")
    void exactlyAtLimit_returnsTrue() throws JsonProcessingException {
      // Arrange
      String permissions =
          IntStream.range(0, 100)
              .mapToObj(i -> "\"read:scope_" + i + "\"")
              .collect(Collectors.joining(",", "[", "]"));
      JsonNode dataNode =
          objectMapper.readTree(
              "{\"pluginId\":\"test-plugin\",\"revokedPermissions\":" + permissions + "}");

      // Act
      boolean valid = eventParser.validatePayload(dataNode);

      // Assert
      assertThat(valid).isTrue();
    }

    @Test
    @DisplayName("Accepts scope at exactly 255 chars (at limit)")
    void scopeAtMaxLength_returnsTrue() throws JsonProcessingException {
      // Arrange
      String scopeAtLimit = "x".repeat(255);
      JsonNode dataNode =
          objectMapper.readTree(
              "{\"pluginId\":\"test-plugin\",\"revokedPermissions\":[\"" + scopeAtLimit + "\"]}");

      // Act
      boolean valid = eventParser.validatePayload(dataNode);

      // Assert
      assertThat(valid).isTrue();
    }
  }

  @Nested
  @DisplayName("pluginId extraction")
  class PluginIdExtraction {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("extracts pluginId from camelCase key")
    void extractPluginId_camelCase() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"pluginId\":\"test-plugin\"}");

      // Act & Assert
      assertThat(eventParser.extractPluginIdFromData(data)).isEqualTo("test-plugin");
    }

    @Test
    @DisplayName("extracts pluginId from snake_case key")
    void extractPluginId_snakeCase() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"plugin_id\":\"test-plugin\"}");

      // Act & Assert
      assertThat(eventParser.extractPluginIdFromData(data)).isEqualTo("test-plugin");
    }

    @Test
    @DisplayName("returns null when pluginId missing")
    void extractPluginId_missing() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"other\":\"value\"}");

      // Act & Assert
      assertThat(eventParser.extractPluginIdFromData(data)).isNull();
    }

    @Test
    @DisplayName("returns null for invalid pluginId format (M-2 — path traversal)")
    void extractPluginId_invalidFormat() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"pluginId\":\"../../etc/passwd\"}");

      // Act & Assert
      assertThat(eventParser.extractPluginIdFromData(data)).isNull();
    }

    @Test
    @DisplayName("returns null for blank pluginId value (M-2)")
    void extractPluginId_blank() throws Exception {
      // Arrange
      var data = mapper.readTree("{\"pluginId\":\" \"}");

      // Act & Assert
      assertThat(eventParser.extractPluginIdFromData(data)).isNull();
    }
  }
}
