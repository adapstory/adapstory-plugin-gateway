package com.adapstory.gateway.filter;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.config.JwtProcessorFactory;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import io.opentelemetry.api.trace.Span;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/**
 * Фильтр аутентификации плагинов.
 *
 * <p>Валидирует JWT плагина через Keycloak JWKS endpoint (с кешированием 5 мин), извлекает claims:
 * plugin_id, adapstory_tenant_id, permissions[], trust_level. Помещает PluginSecurityContext в
 * SecurityContext и request attributes.
 */
@Component
public class PluginAuthFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(PluginAuthFilter.class);
  private static final String BEARER_PREFIX = "Bearer ";
  public static final String PLUGIN_SECURITY_CONTEXT_ATTR = "pluginSecurityContext";

  private final GatewayProperties properties;
  private final ObjectMapper objectMapper;
  private final JwtProcessorFactory jwtProcessorFactory;
  private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

  public PluginAuthFilter(
      GatewayProperties properties,
      ObjectMapper objectMapper,
      JwtProcessorFactory jwtProcessorFactory) {
    this.properties = properties;
    this.objectMapper = objectMapper;
    this.jwtProcessorFactory = jwtProcessorFactory;
  }

  @PostConstruct
  void init() throws java.net.MalformedURLException {
    this.jwtProcessor = jwtProcessorFactory.createJwtProcessor(properties.jwt());
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

    if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
      writeError(
          response,
          request,
          401,
          "Unauthorized",
          "Missing or invalid Authorization header",
          Map.of());
      return;
    }

    String token = authHeader.substring(BEARER_PREFIX.length());

    try {
      JWTClaimsSet claims = jwtProcessor.process(token, null);

      PluginSecurityContext pluginContext = PluginJwtClaimsMapper.mapClaims(claims);

      if (pluginContext == null) {
        writeError(
            response, request, 401, "Unauthorized", "JWT missing required plugin claims", Map.of());
        return;
      }

      request.setAttribute(PLUGIN_SECURITY_CONTEXT_ATTR, pluginContext);

      List<SimpleGrantedAuthority> authorities =
          pluginContext.permissions().stream().map(SimpleGrantedAuthority::new).toList();

      AbstractAuthenticationToken authentication =
          new PluginAuthenticationToken(pluginContext, authorities);
      authentication.setAuthenticated(true);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      Span.current().setAttribute("plugin.id", pluginContext.pluginId());
      Span.current().setAttribute("tenant.id", pluginContext.tenantId());

      filterChain.doFilter(request, response);
    } catch (Exception ex) {
      log.warn("Plugin JWT validation failed: {}", ex.getMessage());
      writeError(
          response, request, 401, "Unauthorized", "Invalid or expired plugin token", Map.of());
    } finally {
      SecurityContextHolder.clearContext();
    }
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return (path.startsWith("/actuator/") || path.startsWith("/api/bc-02/gateway/v1/webhooks"));
  }

  private void writeError(
      HttpServletResponse response,
      HttpServletRequest request,
      int status,
      String error,
      String message,
      Map<String, Object> details)
      throws IOException {
    GatewayErrorWriter.writeError(objectMapper, response, request, status, error, message, details);
  }
}
