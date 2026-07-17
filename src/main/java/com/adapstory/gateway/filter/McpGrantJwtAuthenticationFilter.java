package com.adapstory.gateway.filter;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.config.JwtProcessorFactory;
import com.adapstory.gateway.mcpgrant.McpAccessTokenContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Validates the short-lived Gateway-audience token used by capability-first MCP requests. */
@Component
public final class McpGrantJwtAuthenticationFilter extends OncePerRequestFilter {

  public static final String MCP_ACCESS_TOKEN_ATTR = "mcpAccessTokenContext";

  private static final Logger log = LoggerFactory.getLogger(McpGrantJwtAuthenticationFilter.class);
  private static final String GRANT_PATH = "/internal/mcp-grants/v1";
  private static final String BEARER_PREFIX = "Bearer ";
  private static final int MAX_BEARER_LENGTH = 8192;

  private final GatewayProperties properties;
  private final ObjectMapper objectMapper;
  private final JwtProcessorFactory jwtProcessorFactory;
  private final Set<String> authorizedParties;
  private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

  public McpGrantJwtAuthenticationFilter(
      GatewayProperties properties,
      ObjectMapper objectMapper,
      JwtProcessorFactory jwtProcessorFactory,
      @Value("${gateway.mcp.grants.authorized-parties:adapstory-bc10-service}")
          List<String> authorizedParties) {
    this.properties = Objects.requireNonNull(properties, "properties must not be null");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    this.jwtProcessorFactory =
        Objects.requireNonNull(jwtProcessorFactory, "jwtProcessorFactory must not be null");
    if (authorizedParties == null || authorizedParties.isEmpty()) {
      throw new IllegalArgumentException("at least one MCP grant authorized party is required");
    }
    this.authorizedParties = Set.copyOf(authorizedParties);
  }

  @PostConstruct
  void init() throws java.net.MalformedURLException {
    GatewayProperties.JwtConfig jwt = properties.jwt();
    this.jwtProcessor =
        jwtProcessorFactory.createJwtProcessor(
            jwt.jwksUri(),
            jwt.issuer(),
            Set.of(jwt.audience()),
            Set.of("sub", "iss", "aud", "exp", "jti", "adapstory_tenant_id", "azp"),
            jwt.jwksCacheTtlMinutes());
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (header == null || !header.startsWith(BEARER_PREFIX)) {
      writeError(response, request, 401, "Authentication required");
      return;
    }
    String bearer = header.substring(BEARER_PREFIX.length());
    if (!isCanonicalBearer(bearer)) {
      writeError(response, request, 401, "Invalid access token");
      return;
    }

    JWTClaimsSet claims;
    McpAccessTokenContext context;
    try {
      claims = jwtProcessor.process(bearer, null);
      context = mapContext(claims);
    } catch (Exception exception) {
      log.warn(
          "Gateway-audience MCP JWT validation failed: {}", exception.getClass().getSimpleName());
      writeError(response, request, 401, "Invalid or expired access token");
      return;
    }
    if (claims.getClaim("plugin_tools") != null) {
      writeError(response, request, 401, "Legacy MCP authorization claims are not accepted");
      return;
    }
    if (!authorizedParties.contains(context.authorizedParty())) {
      writeError(response, request, 403, "OAuth client is not authorized for MCP grants");
      return;
    }
    String expectedCaller = "service:" + context.authorizedParty();
    if (!context.tenantId().equals(request.getHeader("X-Tenant-Id"))
        || !expectedCaller.equals(request.getHeader("X-User-Id"))
        || !context.subject().equals(request.getHeader("X-Adapstory-User-Id"))) {
      writeError(response, request, 403, "Request identity does not match signed token claims");
      return;
    }

    request.setAttribute(MCP_ACCESS_TOKEN_ATTR, context);
    request.setAttribute(PluginAuthFilter.AUTHENTICATED_ACTOR_ID_ATTR, context.subject());
    request.setAttribute(PluginMcpJwtClaimFilter.MCP_TENANT_ID_ATTR, context.tenantId());
    var authentication = new PreAuthenticatedAuthenticationToken(context, null, List.of());
    SecurityContextHolder.getContext().setAuthentication(authentication);
    try {
      filterChain.doFilter(request, response);
    } finally {
      SecurityContextHolder.clearContext();
    }
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getRequestURI();
    return !GRANT_PATH.equals(path) && PluginMcpJwtClaimFilter.extractSlug(path) == null;
  }

  private static McpAccessTokenContext mapContext(JWTClaimsSet claims) throws ParseException {
    Date expiration = claims.getExpirationTime();
    if (expiration == null) {
      throw new IllegalArgumentException("access token expiry is required");
    }
    return new McpAccessTokenContext(
        claims.getJWTID(),
        claims.getSubject(),
        claims.getStringClaim("adapstory_tenant_id"),
        claims.getStringClaim("azp"),
        expiration.toInstant());
  }

  private static boolean isCanonicalBearer(String bearer) {
    return !bearer.isBlank()
        && bearer.length() <= MAX_BEARER_LENGTH
        && bearer
            .chars()
            .noneMatch(
                character ->
                    Character.isWhitespace(character) || Character.isISOControl(character));
  }

  private void writeError(
      HttpServletResponse response, HttpServletRequest request, int status, String message)
      throws IOException {
    GatewayErrorWriter.writeError(
        objectMapper,
        response,
        request,
        status,
        status == 401 ? "Unauthorized" : "Forbidden",
        message,
        Map.of());
  }
}
