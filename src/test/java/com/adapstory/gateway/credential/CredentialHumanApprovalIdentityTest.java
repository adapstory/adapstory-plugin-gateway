package com.adapstory.gateway.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CredentialHumanApprovalIdentityTest {

  @Test
  void derivesApprovalAuthorityOnlyFromVerifiedHumanClaims() {
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("human-123")
            .issuer("https://id.adapstory.test/realms/adapstory")
            .claim("acr", "urn:adapstory:acr:credential-approval")
            .claim("realm_access", Map.of("roles", List.of("credential-production-approver")))
            .expirationTime(java.util.Date.from(Instant.now().plusSeconds(60)))
            .build();

    CredentialHumanApprovalIdentity identity =
        CredentialHumanApprovalIdentity.fromClaims(
            claims, "urn:adapstory:acr:credential-approval", "credential-production-approver");

    assertThat(identity.subject()).isEqualTo("human-123");
    assertThat(identity.role()).isEqualTo("credential-production-approver");
  }

  @Test
  void rejectsAgentSubjectsWrongAcrAndMissingRole() {
    JWTClaimsSet base =
        new JWTClaimsSet.Builder()
            .subject("agent:codex")
            .issuer("https://id.adapstory.test/realms/adapstory")
            .claim("acr", "password")
            .claim("realm_access", Map.of("roles", List.of("viewer")))
            .build();

    assertThatThrownBy(
            () ->
                CredentialHumanApprovalIdentity.fromClaims(
                    base,
                    "urn:adapstory:acr:credential-approval",
                    "credential-production-approver"))
        .isInstanceOf(CredentialCapabilityRejectedException.class);
  }
}
