package com.adapstory.gateway.dto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Тесты PluginPermissionsResponse: DTO для ответа BC-02 на запрос permissions.
 *
 * <p>Покрывает: defensive copy, null → empty list, immutability.
 */
@DisplayName("PluginPermissionsResponse")
class PluginPermissionsResponseTest {

  @Test
  @DisplayName("should create Data with permissions list")
  void should_createData_withPermissions() {
    // Act
    var data = new PluginPermissionsResponse.Data("plugin-1", List.of("read:data", "write:data"));

    // Assert
    assertThat(data.pluginId()).isEqualTo("plugin-1");
    assertThat(data.permissions()).containsExactly("read:data", "write:data");
  }

  @Test
  @DisplayName("should create Data with empty list when permissions is null")
  void should_createData_withEmptyList_when_permissionsNull() {
    // Act
    var data = new PluginPermissionsResponse.Data("plugin-1", null);

    // Assert
    assertThat(data.permissions()).isNotNull().isEmpty();
  }

  @Test
  @DisplayName("should create immutable copy of permissions list")
  void should_createImmutableCopy() {
    // Arrange
    var mutableList = new java.util.ArrayList<>(List.of("read:data"));

    // Act
    var data = new PluginPermissionsResponse.Data("plugin-1", mutableList);
    mutableList.add("write:data"); // modify original

    // Assert — data should not be affected
    assertThat(data.permissions()).containsExactly("read:data");
  }

  @Test
  @DisplayName("should create PluginPermissionsResponse with data")
  void should_createResponse_withData() {
    // Act
    var data = new PluginPermissionsResponse.Data("plugin-1", List.of("read:data"));
    var response = new PluginPermissionsResponse(data);

    // Assert
    assertThat(response.data()).isNotNull();
    assertThat(response.data().pluginId()).isEqualTo("plugin-1");
  }

  @Test
  @DisplayName("should handle null data")
  void should_handleNullData() {
    // Act
    var response = new PluginPermissionsResponse(null);

    // Assert
    assertThat(response.data()).isNull();
  }
}
