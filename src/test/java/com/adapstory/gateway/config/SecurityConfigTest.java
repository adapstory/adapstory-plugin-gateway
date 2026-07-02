package com.adapstory.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SecurityConfigTest {

  @Test
  void failClosedUserDetailsService_disablesPasswordBasedUsers() {
    var userDetailsService = new SecurityConfig().failClosedUserDetailsService();
    var userDetails = userDetailsService.loadUserByUsername("user");

    assertThat(userDetails.getUsername()).isEqualTo("disabled-password-auth");
    assertThat(userDetails.isEnabled()).isFalse();
    assertThat(userDetails.getAuthorities())
        .extracting(Object::toString)
        .containsExactly("AUTH_DISABLED");
  }
}
