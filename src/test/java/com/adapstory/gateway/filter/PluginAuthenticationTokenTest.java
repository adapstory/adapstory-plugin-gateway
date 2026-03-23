package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;

import com.adapstory.gateway.dto.PluginSecurityContext;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Тесты PluginAuthenticationToken: Spring Security токен аутентификации плагина.
 *
 * <p>Покрывает: getCredentials, getPrincipal, authorities.
 */
@DisplayName("PluginAuthenticationToken")
class PluginAuthenticationTokenTest {

  @Test
  @DisplayName("should return null credentials")
  void should_returnNullCredentials() {
    // Arrange
    PluginSecurityContext ctx =
        new PluginSecurityContext(
            "adapstory.assessment.quiz", "tenant-1", List.of("content.read"), "CORE");

    // Act
    PluginAuthenticationToken token =
        new PluginAuthenticationToken(ctx, List.of(new SimpleGrantedAuthority("content.read")));

    // Assert
    assertThat(token.getCredentials()).isNull();
  }

  @Test
  @DisplayName("should return PluginSecurityContext as principal")
  void should_returnPluginSecurityContext_asPrincipal() {
    // Arrange
    PluginSecurityContext ctx =
        new PluginSecurityContext(
            "adapstory.assessment.quiz", "tenant-1", List.of("content.read"), "CORE");

    // Act
    PluginAuthenticationToken token =
        new PluginAuthenticationToken(ctx, List.of(new SimpleGrantedAuthority("content.read")));

    // Assert
    assertThat(token.getPrincipal()).isEqualTo(ctx);
    assertThat(token.getPrincipal().pluginId()).isEqualTo("adapstory.assessment.quiz");
    assertThat(token.getPrincipal().tenantId()).isEqualTo("tenant-1");
  }

  @Test
  @DisplayName("should expose granted authorities")
  void should_exposeGrantedAuthorities() {
    // Arrange
    PluginSecurityContext ctx =
        new PluginSecurityContext(
            "adapstory.assessment.quiz",
            "tenant-1",
            List.of("content.read", "submission.read"),
            "CORE");

    // Act
    PluginAuthenticationToken token =
        new PluginAuthenticationToken(
            ctx,
            List.of(
                new SimpleGrantedAuthority("content.read"),
                new SimpleGrantedAuthority("submission.read")));

    // Assert
    assertThat(token.getAuthorities())
        .extracting("authority")
        .containsExactly("content.read", "submission.read");
  }

  @Test
  @DisplayName("should not be authenticated by default")
  void should_notBeAuthenticated_byDefault() {
    // Arrange
    PluginSecurityContext ctx =
        new PluginSecurityContext("adapstory.assessment.quiz", "tenant-1", List.of(), "CORE");

    // Act
    PluginAuthenticationToken token = new PluginAuthenticationToken(ctx, List.of());

    // Assert
    assertThat(token.isAuthenticated()).isFalse();
  }

  @Test
  @DisplayName("should be authenticated when explicitly set")
  void should_beAuthenticated_when_set() {
    // Arrange
    PluginSecurityContext ctx =
        new PluginSecurityContext("adapstory.assessment.quiz", "tenant-1", List.of(), "CORE");

    // Act
    PluginAuthenticationToken token = new PluginAuthenticationToken(ctx, List.of());
    token.setAuthenticated(true);

    // Assert
    assertThat(token.isAuthenticated()).isTrue();
  }
}
