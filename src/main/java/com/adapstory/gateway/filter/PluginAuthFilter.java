package com.adapstory.gateway.filter;

import com.adapstory.gateway.config.BffUserJwtProperties;
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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
  private final BffUserJwtProperties bffUserJwtProperties;
  private final ObjectMapper objectMapper;
  private final JwtProcessorFactory jwtProcessorFactory;
  private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
  private ConfigurableJWTProcessor<SecurityContext> bffUserJwtProcessor;

  public PluginAuthFilter(
      GatewayProperties properties,
      ObjectMapper objectMapper,
      JwtProcessorFactory jwtProcessorFactory) {
    this(properties, new BffUserJwtProperties(), objectMapper, jwtProcessorFactory);
  }

  @Autowired
  public PluginAuthFilter(
      GatewayProperties properties,
      BffUserJwtProperties bffUserJwtProperties,
      ObjectMapper objectMapper,
      JwtProcessorFactory jwtProcessorFactory) {
    this.properties = properties;
    this.bffUserJwtProperties = bffUserJwtProperties;
    this.objectMapper = objectMapper;
    this.jwtProcessorFactory = jwtProcessorFactory;
  }

  @PostConstruct
  void init() throws java.net.MalformedURLException {
    this.jwtProcessor = jwtProcessorFactory.createJwtProcessor(properties.jwt());
    if (bffUserJwtProperties.isEnabled() && !bffUserJwtProperties.getAudiences().isEmpty()) {
      this.bffUserJwtProcessor =
          jwtProcessorFactory.createJwtProcessor(
              properties.jwt().jwksUri(),
              properties.jwt().issuer(),
              Set.copyOf(bffUserJwtProperties.getAudiences()),
              Set.of("iss", "aud", "exp"),
              properties.jwt().jwksCacheTtlMinutes());
    }
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
      List<String> pluginTools = PluginJwtClaimsMapper.mapPluginTools(claims);

      if (pluginContext == null) {
        writeError(
            response, request, 401, "Unauthorized", "JWT missing required plugin claims", Map.of());
        return;
      }

      request.setAttribute(PLUGIN_SECURITY_CONTEXT_ATTR, pluginContext);
      if (pluginTools != null) {
        request.setAttribute(PluginMcpJwtClaimFilter.PLUGIN_TOOLS_ATTR, pluginTools);
      }

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
      if (tryBffUserJwtFallback(token, request, response, filterChain)) {
        return;
      }
      log.warn("Plugin JWT validation failed: {}", ex.getMessage());
      writeError(
          response, request, 401, "Unauthorized", "Invalid or expired plugin token", Map.of());
    } finally {
      SecurityContextHolder.clearContext();
    }
  }

  private boolean tryBffUserJwtFallback(
      String token, HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    String pluginId = pluginSlug(request.getRequestURI());
    if (bffUserJwtProcessor == null || pluginId == null) {
      return false;
    }

    try {
      JWTClaimsSet claims = bffUserJwtProcessor.process(token, null);
      String tenantId =
          firstNonBlank(
              stringClaim(claims, "adapstory_tenant_id"), stringClaim(claims, "tenant_id"));
      if (tenantId == null) {
        writeError(
            response,
            request,
            401,
            "Unauthorized",
            "BFF user token is missing tenant claim",
            Map.of());
        return true;
      }
      List<String> roles = extractRoles(claims);
      if (roles.stream().noneMatch(bffUserJwtProperties.getAllowedRoles()::contains)) {
        writeError(
            response,
            request,
            403,
            "Forbidden",
            "BFF user token does not contain a role allowed for plugin REST access",
            Map.of());
        return true;
      }

      PluginSecurityContext pluginContext =
          new PluginSecurityContext(canonicalPluginId(pluginId), tenantId, List.of(), "BFF_USER");
      request.setAttribute(PLUGIN_SECURITY_CONTEXT_ATTR, pluginContext);

      AbstractAuthenticationToken authentication =
          new PluginAuthenticationToken(pluginContext, List.of());
      authentication.setAuthenticated(true);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      Span.current().setAttribute("plugin.id", pluginContext.pluginId());
      Span.current().setAttribute("tenant.id", pluginContext.tenantId());

      chain.doFilter(request, response);
      return true;
    } catch (Exception fallbackEx) {
      log.warn("BFF user JWT validation failed: {}", fallbackEx.getMessage());
      return false;
    }
  }

  private static String pluginSlug(String path) {
    if (!path.startsWith("/api/plugins/")) {
      return null;
    }
    String suffix = path.substring("/api/plugins/".length());
    int slash = suffix.indexOf('/');
    if (slash <= 0) {
      return null;
    }
    String rest = suffix.substring(slash + 1);
    if (!rest.equals("v1") && !rest.startsWith("v1/")) {
      return null;
    }
    return suffix.substring(0, slash);
  }

  private static String stringClaim(JWTClaimsSet claims, String claim) throws ParseException {
    String value = claims.getStringClaim(claim);
    return value == null || value.isBlank() ? null : value;
  }

  private static String firstNonBlank(String first, String second) {
    return first != null && !first.isBlank() ? first : second;
  }

  private String canonicalPluginId(String routePluginId) {
    return properties.pluginIdAliases().getOrDefault(routePluginId, routePluginId);
  }

  private static List<String> extractRoles(JWTClaimsSet claims) {
    List<String> roles = new ArrayList<>();
    Object realmAccess = claims.getClaim("realm_access");
    if (realmAccess instanceof Map<?, ?> realmMap
        && realmMap.get("roles") instanceof List<?> rawRoles) {
      rawRoles.stream()
          .filter(String.class::isInstance)
          .map(String.class::cast)
          .forEach(roles::add);
    }
    Object groups = claims.getClaim("groups");
    if (groups instanceof List<?> rawGroups) {
      rawGroups.stream()
          .filter(String.class::isInstance)
          .map(String.class::cast)
          .forEach(roles::add);
    }
    return roles;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return (path.startsWith("/actuator/")
        || path.startsWith("/api/bc-02/gateway/v1/webhooks")
        || path.equals("/v3/api-docs")
        || path.startsWith("/v3/api-docs/"));
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
