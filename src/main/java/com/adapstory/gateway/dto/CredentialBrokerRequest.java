package com.adapstory.gateway.dto;

import com.fasterxml.jackson.databind.JsonNode;

public record CredentialBrokerRequest(
    String httpMethod,
    String path,
    JsonNode body,
    String assertion,
    String signature,
    String requestId) {}
