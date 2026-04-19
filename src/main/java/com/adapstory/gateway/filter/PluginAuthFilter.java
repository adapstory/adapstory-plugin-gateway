package com.adapstory.gateway.filter;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.opentelemetry.api.trace.Span;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
  private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

  public PluginAuthFilter(GatewayProperties properties, ObjectMapper objectMapper) {
    this.properties = properties;
    this.objectMapper = objectMapper;
  }

  @PostConstruct
  void init() throws java.net.MalformedURLException {
    GatewayProperties.JwtConfig jwtConfig = properties.jwt();

    JWKSource<SecurityContext> jwkSource =
        JWKSourceBuilder.create(URI.create(jwtConfig.jwksUri()).toURL())
            .cache(jwtConfig.jwksCacheTtlMinutes() * 60L * 1000L, 60_000L)
            .build();

    JWSKeySelector<SecurityContext> keySelector =
        new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

    DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier =
        new DefaultJWTClaimsVerifier<>(
            new JWTClaimsSet.Builder()
                .issuer(jwtConfig.issuer())
                .audience(jwtConfig.audience())
                .build(),
            Set.of("sub", "iss", "aud", "exp", "plugin_id", "adapstory_tenant_id", "permissions"));

    ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT));
    processor.setJWSKeySelector(keySelector);
    processor.setJWTClaimsSetVerifier(claimsVerifier);

    this.jwtProcessor = processor;
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

      String pluginId = claims.getStringClaim("plugin_id");
      String tenantId = claims.getStringClaim("adapstory_tenant_id");
      List<String> permissions = claims.getStringListClaim("permissions");
      String trustLevel = claims.getStringClaim("trust_level");

      if (pluginId == null || tenantId == null || permissions == null) {
        writeError(
            response, request, 401, "Unauthorized", "JWT missing required plugin claims", Map.of());
        return;
      }

      PluginSecurityContext pluginContext =
          new PluginSecurityContext(pluginId, tenantId, List.copyOf(permissions), trustLevel);

      request.setAttribute(PLUGIN_SECURITY_CONTEXT_ATTR, pluginContext);

      List<SimpleGrantedAuthority> authorities =
          permissions.stream().map(SimpleGrantedAuthority::new).toList();

      AbstractAuthenticationToken authentication =
          new PluginAuthenticationToken(pluginContext, authorities);
      authentication.setAuthenticated(true);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      Span currentSpan = Span.current();
      currentSpan.setAttribute("plugin.id", pluginId);
      currentSpan.setAttribute("tenant.id", tenantId);

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
