package com.adapstory.gateway.config;

import com.adapstory.gateway.filter.HeaderInjectionFilter;
import com.adapstory.gateway.filter.PermissionEnforcementFilter;
import com.adapstory.gateway.filter.PluginAuthFilter;
import com.adapstory.gateway.filter.PluginInstalledCheckFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Конфигурация безопасности Plugin Gateway.
 *
 * <p>Использует Keycloak JWKS для валидации JWT токенов плагинов. Публичные эндпоинты: actuator
 * health, внутренние webhook-и.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  @Order(0)
  SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
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
  }

  @Bean
  @Order(1)
  SecurityFilterChain gatewayFilterChain(
      HttpSecurity http,
      PluginAuthFilter pluginAuthFilter,
      PluginInstalledCheckFilter pluginInstalledCheckFilter,
      PermissionEnforcementFilter permissionEnforcementFilter,
      HeaderInjectionFilter headerInjectionFilter)
      throws Exception {
    return http.securityMatcher("/**")
        .csrf(AbstractHttpConfigurer::disable)
        .cors(AbstractHttpConfigurer::disable)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            // L3: /internal/** is open — security relies on K8s NetworkPolicy restricting
            // access to core BCs only. Consider adding shared-secret header check for defense in
            // depth.
            auth -> auth.requestMatchers("/internal/**").permitAll().anyRequest().authenticated())
        .addFilterBefore(pluginAuthFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(pluginInstalledCheckFilter, PluginAuthFilter.class)
        .addFilterAfter(permissionEnforcementFilter, PluginInstalledCheckFilter.class)
        .addFilterAfter(headerInjectionFilter, PermissionEnforcementFilter.class)
        .formLogin(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .build();
  }

  // Filters are added to the Security filter chain above.
  // Disable Servlet auto-registration to prevent duplicate filter initialization by Tomcat.

  @Bean
  FilterRegistrationBean<PluginAuthFilter> disablePluginAuthAutoRegistration(
      PluginAuthFilter filter) {
    var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }

  @Bean
  FilterRegistrationBean<PermissionEnforcementFilter> disablePermissionFilterAutoRegistration(
      PermissionEnforcementFilter filter) {
    var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }

  @Bean
  FilterRegistrationBean<PluginInstalledCheckFilter> disableInstalledCheckAutoRegistration(
      PluginInstalledCheckFilter filter) {
    var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }

  @Bean
  FilterRegistrationBean<HeaderInjectionFilter> disableHeaderFilterAutoRegistration(
      HeaderInjectionFilter filter) {
    var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }
}
