package com.adapstory.gateway.credential;

import java.util.Arrays;

public enum CredentialCapability {
  PLAN("credential.lifecycle.plan"),
  APPLY("credential.lifecycle.apply"),
  STATUS("credential.lifecycle.status"),
  CANCEL("credential.lifecycle.cancel"),
  CONTAIN("credential.lifecycle.contain");

  private final String wireValue;

  CredentialCapability(String wireValue) {
    this.wireValue = wireValue;
  }

  public String wireValue() {
    return wireValue;
  }

  /** Resolves only a complete canonical capability name; prefixes and suffixes are denied. */
  public static CredentialCapability requireExact(String value) {
    return Arrays.stream(values())
        .filter(candidate -> candidate.wireValue.equals(value))
        .findFirst()
        .orElseThrow(
            () -> new CredentialCapabilityRejectedException("unsupported credential capability"));
  }
}
