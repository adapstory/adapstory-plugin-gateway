package com.adapstory.gateway.filter;

import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.config.JwtProcessorFactory;
import com.adapstory.gateway.credential.CredentialCapabilityRejectedException;
import com.adapstory.gateway.credential.CredentialHumanApprovalIdentity;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
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
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public final class CredentialHumanApprovalAuthenticationFilter extends OncePerRequestFilter {

  private static final String APPROVAL_SUFFIX = "/approvals";
  private static final String BEARER_PREFIX = "Bearer ";

  private final GatewayProperties gatewayProperties;
  private final JwtProcessorFactory jwtProcessorFactory;
  private final ObjectMapper objectMapper;
  private final String requiredAcr;
  private final String requiredRole;
  private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

  public CredentialHumanApprovalAuthenticationFilter(
      GatewayProperties gatewayProperties,
      JwtProcessorFactory jwtProcessorFactory,
      ObjectMapper objectMapper,
      @Value("${gateway.credential-lifecycle.approval-acr:urn:adapstory:acr:credential-approval}")
          String requiredAcr,
      @Value("${gateway.credential-lifecycle.approval-role:credential-production-approver}")
          String requiredRole) {
    this.gatewayProperties = gatewayProperties;
    this.jwtProcessorFactory = jwtProcessorFactory;
    this.objectMapper = objectMapper;
    this.requiredAcr = requiredAcr;
    this.requiredRole = requiredRole;
  }

  @PostConstruct
  void init() throws java.net.MalformedURLException {
    GatewayProperties.JwtConfig jwt = gatewayProperties.jwt();
    jwtProcessor =
        jwtProcessorFactory.createJwtProcessor(
            jwt.jwksUri(),
            jwt.issuer(),
            Set.of(jwt.audience()),
            Set.of("sub", "iss", "aud", "exp", "jti", "acr", "realm_access"),
            jwt.jwksCacheTtlMinutes());
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !request.getRequestURI().startsWith("/internal/credential-lifecycle/v1/plans/")
        || !request.getRequestURI().endsWith(APPROVAL_SUFFIX);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
      deny(response);
      return;
    }
    CredentialHumanApprovalIdentity identity;
    try {
      JWTClaimsSet claims =
          jwtProcessor.process(authorization.substring(BEARER_PREFIX.length()), null);
      identity = CredentialHumanApprovalIdentity.fromClaims(claims, requiredAcr, requiredRole);
    } catch (ParseException
        | BadJOSEException
        | JOSEException
        | CredentialCapabilityRejectedException exception) {
      deny(response);
      return;
    }
    var authentication =
        new PreAuthenticatedAuthenticationToken(
            identity, null, List.of(new SimpleGrantedAuthority(requiredRole)));
    SecurityContextHolder.getContext().setAuthentication(authentication);
    try {
      filterChain.doFilter(request, response);
    } finally {
      SecurityContextHolder.clearContext();
    }
  }

  private void deny(HttpServletResponse response) throws IOException {
    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    response.setContentType("application/problem+json");
    objectMapper.writeValue(
        response.getOutputStream(), java.util.Map.of("type", "human_approval_denied"));
  }
}
