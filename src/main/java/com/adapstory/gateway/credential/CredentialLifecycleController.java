package com.adapstory.gateway.credential;

import com.adapstory.gateway.dto.CredentialBrokerResponse;
import com.adapstory.gateway.dto.CredentialHumanApprovalRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/credential-lifecycle/v1")
@ConditionalOnProperty(name = "gateway.credential-lifecycle.enabled", havingValue = "true")
public final class CredentialLifecycleController {

  private final CredentialLifecycleForwarder forwarder;
  private final CredentialHumanApprovalForwarder humanApprovalForwarder;
  private final ObjectMapper objectMapper;

  public CredentialLifecycleController(
      CredentialLifecycleForwarder forwarder,
      CredentialHumanApprovalForwarder humanApprovalForwarder,
      ObjectMapper objectMapper) {
    this.forwarder = forwarder;
    this.humanApprovalForwarder = humanApprovalForwarder;
    this.objectMapper = objectMapper;
  }

  @PostMapping("/plans")
  @PermitAll
  ResponseEntity<JsonNode> plan(@RequestBody JsonNode body, HttpServletRequest request) {
    return response(
        forwarder.forward(
            CredentialCapability.PLAN, "POST /v1/plans", "/v1/plans", body, headers(request)));
  }

  @PostMapping("/operations")
  @PermitAll
  ResponseEntity<JsonNode> apply(@RequestBody JsonNode body, HttpServletRequest request) {
    return response(
        forwarder.forward(
            CredentialCapability.APPLY,
            "POST /v1/operations",
            "/v1/operations",
            body,
            headers(request)));
  }

  @GetMapping("/operations/{operationRef}")
  @PermitAll
  ResponseEntity<JsonNode> status(@PathVariable String operationRef, HttpServletRequest request) {
    requireOperationRef(operationRef);
    JsonNode bindingBody = objectMapper.createObjectNode().put("operation_ref", operationRef);
    return response(
        forwarder.forward(
            CredentialCapability.STATUS,
            "GET /v1/operations/{operation_ref}",
            "/v1/operations/" + operationRef,
            bindingBody,
            headers(request)));
  }

  @PostMapping("/operations/{operationRef}/cancel")
  @PermitAll
  ResponseEntity<JsonNode> cancel(
      @PathVariable String operationRef,
      @RequestBody(required = false) JsonNode body,
      HttpServletRequest request) {
    requireOperationRef(operationRef);
    JsonNode requestBody =
        body == null ? objectMapper.createObjectNode().put("operation_ref", operationRef) : body;
    return response(
        forwarder.forward(
            CredentialCapability.CANCEL,
            "POST /v1/operations/{operation_ref}/cancel",
            "/v1/operations/" + operationRef + "/cancel",
            requestBody,
            headers(request)));
  }

  @PostMapping("/containments")
  @PermitAll
  ResponseEntity<JsonNode> contain(@RequestBody JsonNode body, HttpServletRequest request) {
    return response(
        forwarder.forward(
            CredentialCapability.CONTAIN,
            "POST /v1/containments",
            "/v1/containments",
            body,
            headers(request)));
  }

  @PostMapping("/plans/{planRef}/approvals")
  @PreAuthorize("isAuthenticated()")
  ResponseEntity<JsonNode> approve(
      @PathVariable String planRef,
      @RequestBody CredentialHumanApprovalRequest approval,
      HttpServletRequest request,
      Authentication authentication) {
    if (planRef == null || !planRef.matches("^plan_[a-f0-9]{32,64}$")) {
      throw new CredentialCapabilityRejectedException("invalid plan reference");
    }
    if (authentication == null
        || !(authentication.getPrincipal() instanceof CredentialHumanApprovalIdentity identity)) {
      throw new CredentialCapabilityRejectedException("human approval identity is required");
    }
    JsonNode body =
        objectMapper
            .createObjectNode()
            .put("plan_digest", approval.planDigest())
            .put("subject", identity.subject())
            .put("issuer", identity.issuer())
            .put("acr", identity.acr())
            .put("role", identity.role())
            .put("nonce", approval.nonce())
            .put("expires_at", approval.expiresAt());
    return response(
        humanApprovalForwarder.forward(planRef, body, request.getHeader("X-Request-Id"), identity));
  }

  private static ResponseEntity<JsonNode> response(CredentialBrokerResponse response) {
    return ResponseEntity.status(response.status()).body(response.body());
  }

  private static CredentialAgentHeaders headers(HttpServletRequest request) {
    return new CredentialAgentHeaders(
        request.getHeader("X-Credential-Task-Attestation"),
        request.getHeader("X-Credential-Task-Signature"),
        request.getHeader("X-Beads-Task-Id"),
        request.getHeader("X-Agent-Instance-Id"),
        request.getHeader("X-Codex-Thread-Id"),
        request.getHeader("X-Human-Message-Digest"),
        request.getHeader("X-Credential-Policy-Digest"),
        request.getHeader("X-Request-Id"));
  }

  private static void requireOperationRef(String operationRef) {
    if (operationRef == null || !operationRef.matches("^op_[a-f0-9]{32}$")) {
      throw new CredentialCapabilityRejectedException("invalid operation reference");
    }
  }
}
