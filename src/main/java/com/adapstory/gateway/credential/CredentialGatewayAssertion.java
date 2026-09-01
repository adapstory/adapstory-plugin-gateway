package com.adapstory.gateway.credential;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CredentialGatewayAssertion(
    String version,
    String method,
    @JsonProperty("body_digest") String bodyDigest,
    @JsonProperty("request_id") String requestId,
    String audience,
    String capability,
    @JsonProperty("capability_id") String capabilityId,
    @JsonProperty("task_id") String taskId,
    @JsonProperty("agent_instance_id") String agentInstanceId,
    @JsonProperty("issued_at") long issuedAt,
    @JsonProperty("expires_at") long expiresAt,
    String nonce) {}
