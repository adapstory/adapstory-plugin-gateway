package com.adapstory.gateway.credential;

public record SignedGatewayAssertion(String assertion, String signature) {}
