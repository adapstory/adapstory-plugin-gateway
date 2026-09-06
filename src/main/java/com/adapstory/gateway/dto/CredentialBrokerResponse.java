package com.adapstory.gateway.dto;

import tools.jackson.databind.JsonNode;

public record CredentialBrokerResponse(int status, JsonNode body) {}
