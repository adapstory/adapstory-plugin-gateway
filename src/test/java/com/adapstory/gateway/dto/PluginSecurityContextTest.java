package com.adapstory.gateway.dto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Тесты PluginSecurityContext: record DTO контекста безопасности плагина.
 *
 * <p>Покрывает: все поля, null trust level, empty permissions, various field combinations.
 */
@DisplayName("PluginSecurityContext")
class PluginSecurityContextTest {

  // ── Parameterized: field storage correctness ──

  static Stream<Arguments> contextVariants() {
    return Stream.of(
        Arguments.of(
            "all fields populated",
            "adapstory.assessment.quiz",
            "tenant-uuid",
            List.of("content.read", "submission.read"),
            "CORE"),
        Arguments.of(
            "null trust level",
            "adapstory.assessment.quiz",
            "tenant-uuid",
            List.of("content.read"),
            null),
        Arguments.of(
            "empty permissions list",
            "adapstory.assessment.quiz",
            "tenant-uuid",
            List.of(),
            "CORE"),
        Arguments.of(
            "COMMUNITY trust level",
            "vendor.category.plugin",
            "t-001",
            List.of("content.read"),
            "COMMUNITY"),
        Arguments.of(
            "VERIFIED trust level",
            "org.unit.tool",
            "t-002",
            List.of("content.read", "content.write"),
            "VERIFIED"),
        Arguments.of(
            "single-element permissions",
            "adapstory.education_module.ai-grader",
            "tenant-1",
            List.of("submission.read"),
            "CORE"));
  }

  @ParameterizedTest(name = "[{index}] {0}")
  @MethodSource("contextVariants")
  @DisplayName("should store all fields correctly for various combinations")
  void should_storeFieldsCorrectly(
      String description,
      String pluginId,
      String tenantId,
      List<String> permissions,
      String trustLevel) {
    // Act
    var ctx = new PluginSecurityContext(pluginId, tenantId, permissions, trustLevel);

    // Assert
    assertThat(ctx.pluginId()).as("pluginId for '%s'", description).isEqualTo(pluginId);
    assertThat(ctx.tenantId()).as("tenantId for '%s'", description).isEqualTo(tenantId);
    assertThat(ctx.permissions())
        .as("permissions for '%s'", description)
        .containsExactlyElementsOf(permissions);
    assertThat(ctx.trustLevel()).as("trustLevel for '%s'", description).isEqualTo(trustLevel);
  }

  // ── Parameterized: record equality ──

  static Stream<Arguments> equalityVariants() {
    var base =
        new PluginSecurityContext(
            "adapstory.assessment.quiz", "tenant-uuid", List.of("content.read"), "CORE");

    return Stream.of(
        Arguments.of(
            "same fields",
            base,
            new PluginSecurityContext(
                "adapstory.assessment.quiz", "tenant-uuid", List.of("content.read"), "CORE"),
            true),
        Arguments.of(
            "different pluginId",
            base,
            new PluginSecurityContext(
                "other.quiz.tool", "tenant-uuid", List.of("content.read"), "CORE"),
            false),
        Arguments.of(
            "different tenantId",
            base,
            new PluginSecurityContext(
                "adapstory.assessment.quiz", "other-tenant", List.of("content.read"), "CORE"),
            false),
        Arguments.of(
            "different permissions",
            base,
            new PluginSecurityContext(
                "adapstory.assessment.quiz", "tenant-uuid", List.of("content.write"), "CORE"),
            false),
        Arguments.of(
            "different trustLevel",
            base,
            new PluginSecurityContext(
                "adapstory.assessment.quiz", "tenant-uuid", List.of("content.read"), "COMMUNITY"),
            false),
        Arguments.of(
            "null vs non-null trustLevel",
            base,
            new PluginSecurityContext(
                "adapstory.assessment.quiz", "tenant-uuid", List.of("content.read"), null),
            false));
  }

  @ParameterizedTest(name = "[{index}] {0} → equal={3}")
  @MethodSource("equalityVariants")
  @DisplayName("Record equality is based on all fields")
  void should_varyByField_when_recordEquality(
      String description, PluginSecurityContext a, PluginSecurityContext b, boolean expectEqual) {
    if (expectEqual) {
      assertThat(a).as(description).isEqualTo(b);
      assertThat(a.hashCode()).as(description).isEqualTo(b.hashCode());
    } else {
      assertThat(a).as(description).isNotEqualTo(b);
    }
  }

  // ── Edge cases kept as individual tests for clarity ──

  @Test
  @DisplayName("permissions list is the same reference (record semantics)")
  void should_sameReference_when_permissions() {
    List<String> perms = List.of("content.read");
    var ctx = new PluginSecurityContext("p", "t", perms, "CORE");

    assertThat(ctx.permissions()).isSameAs(perms);
  }

  @Test
  @DisplayName("toString contains all field values")
  void should_containAllFields_when_toString() {
    var ctx =
        new PluginSecurityContext(
            "adapstory.assessment.quiz", "tenant-uuid", List.of("content.read"), "CORE");

    String str = ctx.toString();
    assertThat(str).contains("adapstory.assessment.quiz", "tenant-uuid", "CORE");
  }
}
