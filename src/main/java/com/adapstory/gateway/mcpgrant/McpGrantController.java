package com.adapstory.gateway.mcpgrant;

import com.adapstory.gateway.dto.DelegatedCapabilityAuthorityRequest;
import com.adapstory.gateway.dto.McpGrantRegistrationRequest;
import com.adapstory.gateway.dto.ProviderBindingGrantRequest;
import com.adapstory.gateway.filter.HeaderInjectionFilter;
import com.adapstory.gateway.filter.McpGrantJwtAuthenticationFilter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Objects;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Private endpoint that binds one exchanged access-token jti to exact provider resources. */
@RestController
@PermitAll
@SecurityScheme(
    name = "mcpGatewayBearer",
    type = SecuritySchemeType.HTTP,
    in = SecuritySchemeIn.HEADER,
    scheme = "bearer",
    bearerFormat = "JWT",
    description = "Short-lived Gateway-audience token issued by OAuth token exchange")
public class McpGrantController {

  private final McpGrantService service;

  /** Creates the private grant-registration endpoint. */
  public McpGrantController(McpGrantService service) {
    this.service = Objects.requireNonNull(service, "service must not be null");
  }

  /** Revalidates and stores the complete binding set for the validated exchanged token. */
  @Operation(
      summary = "Register exact MCP provider bindings for an exchanged access token",
      description =
          "Revalidates the complete capability binding set through Plugin Lifecycle and stores "
              + "one immutable, short-lived authorization record keyed by the token jti hash.")
  @ApiResponse(responseCode = "204", description = "Exact token-bound grant registered")
  @ApiResponse(responseCode = "401", description = "Gateway access token is invalid")
  @ApiResponse(responseCode = "403", description = "Signed and asserted identity differ")
  @ApiResponse(responseCode = "409", description = "Binding set is ambiguous or token is rebound")
  @ApiResponse(responseCode = "422", description = "Binding metadata is stale or invalid")
  @ApiResponse(responseCode = "503", description = "Lifecycle or Redis is unavailable")
  @SecurityRequirement(name = "mcpGatewayBearer")
  @Parameters({
    @Parameter(
        name = "X-Tenant-Id",
        in = ParameterIn.HEADER,
        required = true,
        description = "Tenant claim; must exactly match the signed access token",
        schema = @Schema(maxLength = 512)),
    @Parameter(
        name = "X-User-Id",
        in = ParameterIn.HEADER,
        required = true,
        description = "Authenticated caller identity in service:<azp> form",
        schema = @Schema(example = "service:adapstory-bc10-gateway-exchange", maxLength = 512)),
    @Parameter(
        name = "X-Adapstory-User-Id",
        in = ParameterIn.HEADER,
        required = true,
        description = "Delegated actor identity; must exactly match the exchanged token subject",
        schema = @Schema(maxLength = 512))
  })
  @PostMapping("/internal/mcp-grants/v1")
  public ResponseEntity<Void> register(
      @io.swagger.v3.oas.annotations.parameters.RequestBody(
              description = "Complete exact provider binding set for the exchanged access token",
              required = true)
          @RequestBody
          McpGrantRegistrationRequest registration,
      HttpServletRequest request) {
    McpAccessTokenContext token =
        (McpAccessTokenContext)
            request.getAttribute(McpGrantJwtAuthenticationFilter.MCP_ACCESS_TOKEN_ATTR);
    if (token == null) {
      throw new McpGrantRejectedException(
          McpGrantRejectedException.Reason.IDENTITY_MISMATCH,
          "validated Gateway token context is required");
    }
    service.register(
        token,
        trustedIdentity(request, HeaderInjectionFilter.TRUSTED_TENANT_ID_ATTR),
        trustedIdentity(request, HeaderInjectionFilter.TRUSTED_ADAPSTORY_USER_ID_ATTR),
        registration.providerBindings().stream().map(McpGrantController::toDomain).toList(),
        toDomain(registration.delegatedAuthority()));
    return ResponseEntity.noContent().build();
  }

  private static ProviderBindingGrant toDomain(ProviderBindingGrantRequest request) {
    return new ProviderBindingGrant(
        request.capability(),
        request.routeSlug(),
        request.toolName(),
        request.toolVersion(),
        request.inputSchemaVersion(),
        request.inputSchemaDigest(),
        request.authPolicy(),
        request.trustLevel(),
        request.tenantVisibility(),
        request.status(),
        request.lastValidatedAt(),
        request.description());
  }

  private static DelegatedCapabilityAuthority toDomain(
      DelegatedCapabilityAuthorityRequest request) {
    if (request == null) {
      return null;
    }
    return new DelegatedCapabilityAuthority(
        java.util.UUID.fromString(request.runId()),
        request.nodeId(),
        java.util.UUID.fromString(request.grantId()),
        request.policyVersion(),
        request.capabilities());
  }

  private static String trustedIdentity(HttpServletRequest request, String attributeName) {
    Object value = request.getAttribute(attributeName);
    return value instanceof String identity && !identity.isBlank() ? identity : null;
  }
}
