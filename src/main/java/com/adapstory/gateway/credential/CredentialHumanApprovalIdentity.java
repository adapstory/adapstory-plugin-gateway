package com.adapstory.gateway.credential;

import com.nimbusds.jwt.JWTClaimsSet;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

public record CredentialHumanApprovalIdentity(
    String subject, String issuer, String acr, String role) {

  /** Derives a non-agent approval identity from already signature-verified OIDC claims. */
  public static CredentialHumanApprovalIdentity fromClaims(
      JWTClaimsSet claims, String requiredAcr, String requiredRole) {
    try {
      String subject = claims.getSubject();
      String issuer = claims.getIssuer();
      String acr = claims.getStringClaim("acr");
      Map<String, Object> realmAccess = claims.getJSONObjectClaim("realm_access");
      Object rawRoles = realmAccess == null ? null : realmAccess.get("roles");
      boolean hasRole =
          rawRoles instanceof List<?> roles && roles.stream().anyMatch(requiredRole::equals);
      if (subject == null
          || subject.isBlank()
          || subject.startsWith("agent:")
          || issuer == null
          || issuer.isBlank()
          || !requiredAcr.equals(acr)
          || !hasRole) {
        throw new CredentialCapabilityRejectedException(
            "human approval identity requirements are not satisfied");
      }
      return new CredentialHumanApprovalIdentity(subject, issuer, acr, requiredRole);
    } catch (ParseException exception) {
      throw new CredentialCapabilityRejectedException("human approval claims are invalid");
    }
  }
}
