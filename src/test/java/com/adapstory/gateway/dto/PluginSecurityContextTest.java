package com.adapstory.gateway.dto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Тесты PluginSecurityContext: record DTO контекста безопасности плагина.
 *
 * <p>Покрывает: все поля, null trust level, empty permissions.
 */
@DisplayName("PluginSecurityContext")
class PluginSecurityContextTest {

  @Test
  @DisplayName("should store all fields correctly")
  void should_storeAllFields() {
    // Act
    var ctx =
        new PluginSecurityContext(
            "adapstory.assessment.quiz",
            "tenant-uuid",
            List.of("content.read", "submission.read"),
            "CORE");

    // Assert
    assertThat(ctx.pluginId()).isEqualTo("adapstory.assessment.quiz");
    assertThat(ctx.tenantId()).isEqualTo("tenant-uuid");
    assertThat(ctx.permissions()).containsExactly("content.read", "submission.read");
    assertThat(ctx.trustLevel()).isEqualTo("CORE");
  }

  @Test
  @DisplayName("should handle null trust level")
  void should_handleNullTrustLevel() {
    // Act
    var ctx =
        new PluginSecurityContext(
            "adapstory.assessment.quiz", "tenant-uuid", List.of("content.read"), null);

    // Assert
    assertThat(ctx.trustLevel()).isNull();
  }

  @Test
  @DisplayName("should handle empty permissions list")
  void should_handleEmptyPermissions() {
    // Act
    var ctx =
        new PluginSecurityContext("adapstory.assessment.quiz", "tenant-uuid", List.of(), "CORE");

    // Assert
    assertThat(ctx.permissions()).isEmpty();
  }
}
