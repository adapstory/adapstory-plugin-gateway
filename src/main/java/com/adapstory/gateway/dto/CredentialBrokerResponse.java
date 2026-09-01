package com.adapstory.gateway.dto;

import com.fasterxml.jackson.databind.JsonNode;

public record CredentialBrokerResponse(int status, JsonNode body) {}
