package com.adapstory.gateway.config;

import com.adapstory.gateway.filter.HeaderInjectionFilter;
import com.adapstory.gateway.filter.McpGrantJwtAuthenticationFilter;
import com.adapstory.gateway.filter.McpGrantRegistrationBodyLimitFilter;
import com.adapstory.gateway.filter.PermissionEnforcementFilter;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.adapstory.gateway.filter.PluginInstalledCheckFilter;
import com.adapstory.gateway.filter.PluginMcpJwtClaimFilter;
import java.util.UUID;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Конфигурация безопасности Plugin Gateway.
 *
 * <p>Использует Keycloak JWKS для валидации JWT токенов плагинов. Публичные эндпоинты: actuator
 * health, webhook-и.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private static final String DISABLED_AUTHORITY = "AUTH_DISABLED";

  @Bean
  UserDetailsService failClosedUserDetailsService() {
    return username ->
        User.withUsername("disabled-password-auth")
            .password("{noop}" + UUID.randomUUID())
            .authorities(DISABLED_AUTHORITY)
            .disabled(true)
            .build();
  }

  @Bean
  @Order(0)
  SecurityFilterChain actuatorFilterChain(HttpSecurity http) {
    try {
      return http.securityMatcher("/actuator/**")
          .csrf(AbstractHttpConfigurer::disable)
          .authorizeHttpRequests(
              auth ->
                  auth.requestMatchers(
                          "/actuator/health",
                          "/actuator/health/**",
                          "/actuator/info",
                          "/actuator/prometheus")
                      .permitAll()
                      .anyRequest()
                      .denyAll())
          .sessionManagement(
              session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .build();
    } catch (Exception ex) {
      throw new IllegalStateException("Failed to build actuator security filter chain", ex);
    }
  }

  @Bean
  @Order(1)
  SecurityFilterChain mcpFilterChain(
      HttpSecurity http,
      McpGrantJwtAuthenticationFilter mcpGrantJwtAuthenticationFilter,
      McpGrantRegistrationBodyLimitFilter mcpGrantRegistrationBodyLimitFilter,
      PluginMcpJwtClaimFilter pluginMcpJwtClaimFilter,
      HeaderInjectionFilter headerInjectionFilter) {
    try {
      return http.securityMatcher("/internal/plugins/v1/*/mcp", "/internal/mcp-grants/v1")
          .csrf(AbstractHttpConfigurer::disable)
          .cors(AbstractHttpConfigurer::disable)
          .sessionManagement(
              session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
          .addFilterBefore(
              mcpGrantJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
          .addFilterAfter(
              mcpGrantRegistrationBodyLimitFilter, McpGrantJwtAuthenticationFilter.class)
          .addFilterAfter(pluginMcpJwtClaimFilter, McpGrantRegistrationBodyLimitFilter.class)
          .addFilterAfter(headerInjectionFilter, PluginMcpJwtClaimFilter.class)
          .formLogin(AbstractHttpConfigurer::disable)
          .httpBasic(AbstractHttpConfigurer::disable)
          .logout(AbstractHttpConfigurer::disable)
          .build();
    } catch (Exception ex) {
      throw new IllegalStateException("Failed to build MCP security filter chain", ex);
    }
  }

  @Bean
  @Order(2)
  SecurityFilterChain gatewayFilterChain(
      HttpSecurity http,
      PluginAuthFilter pluginAuthFilter,
      PluginInstalledCheckFilter pluginInstalledCheckFilter,
      PermissionEnforcementFilter permissionEnforcementFilter,
      HeaderInjectionFilter headerInjectionFilter) {
    try {
      return http.securityMatcher("/**")
          .csrf(AbstractHttpConfigurer::disable)
          .cors(AbstractHttpConfigurer::disable)
          .sessionManagement(
              session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .authorizeHttpRequests(
              auth ->
                  auth.requestMatchers(
                          "/api/bc-02/gateway/v1/webhooks/**", "/v3/api-docs", "/v3/api-docs/**")
                      .permitAll()
                      .anyRequest()
                      .authenticated())
          .addFilterBefore(pluginAuthFilter, UsernamePasswordAuthenticationFilter.class)
          .addFilterAfter(pluginInstalledCheckFilter, PluginAuthFilter.class)
          .addFilterAfter(permissionEnforcementFilter, PluginInstalledCheckFilter.class)
          .addFilterAfter(headerInjectionFilter, PermissionEnforcementFilter.class)
          .formLogin(AbstractHttpConfigurer::disable)
          .httpBasic(AbstractHttpConfigurer::disable)
          .logout(AbstractHttpConfigurer::disable)
          .build();
    } catch (Exception ex) {
      throw new IllegalStateException("Failed to build gateway security filter chain", ex);
    }
  }

  // Filters are added to the Security filter chain above.
  // Disable Servlet auto-registration to prevent duplicate filter initialization by Tomcat.

  @Bean
  FilterRegistrationBean<PluginAuthFilter> disablePluginAuthAutoRegistration(
      PluginAuthFilter filter) {
    return disableAutoRegistration(filter);
  }

  @Bean
  FilterRegistrationBean<PermissionEnforcementFilter> disablePermissionFilterAutoRegistration(
      PermissionEnforcementFilter filter) {
    return disableAutoRegistration(filter);
  }

  @Bean
  FilterRegistrationBean<PluginInstalledCheckFilter> disableInstalledCheckAutoRegistration(
      PluginInstalledCheckFilter filter) {
    return disableAutoRegistration(filter);
  }

  @Bean
  FilterRegistrationBean<HeaderInjectionFilter> disableHeaderFilterAutoRegistration(
      HeaderInjectionFilter filter) {
    return disableAutoRegistration(filter);
  }

  @Bean
  FilterRegistrationBean<PluginMcpJwtClaimFilter> disableMcpFilterAutoRegistration(
      PluginMcpJwtClaimFilter filter) {
    return disableAutoRegistration(filter);
  }

  @Bean
  FilterRegistrationBean<McpGrantJwtAuthenticationFilter>
      disableMcpGrantJwtAuthenticationAutoRegistration(McpGrantJwtAuthenticationFilter filter) {
    return disableAutoRegistration(filter);
  }

  @Bean
  FilterRegistrationBean<McpGrantRegistrationBodyLimitFilter>
      disableMcpGrantRegistrationBodyLimitAutoRegistration(
          McpGrantRegistrationBodyLimitFilter filter) {
    return disableAutoRegistration(filter);
  }

  private <T extends OncePerRequestFilter> FilterRegistrationBean<T> disableAutoRegistration(
      T filter) {
    var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }
}
