package com.adapstory.gateway.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

class SecurityConfigTest {

  @Test
  void failClosedUserDetailsService_disablesPasswordBasedUsers() {
    var userDetailsService = new SecurityConfig().failClosedUserDetailsService();

    assertThatThrownBy(() -> userDetailsService.loadUserByUsername("user"))
        .isInstanceOf(UsernameNotFoundException.class)
        .hasMessage("Password-based users are disabled");
  }
}
