package com.adapstory.gateway.mcpgrant;

/** Typed result of fail-closed Plugin Lifecycle binding revalidation. */
public final class ProviderBindingVerificationException extends RuntimeException {

  public enum Reason {
    CONFLICT,
    INVALID,
    UNAVAILABLE
  }

  private final Reason reason;

  public ProviderBindingVerificationException(Reason reason) {
    super(
        "provider binding verification failed: "
            + reason.name().toLowerCase(java.util.Locale.ROOT));
    this.reason = reason;
  }

  ProviderBindingVerificationException(Reason reason, Throwable cause) {
    super(
        "provider binding verification failed: " + reason.name().toLowerCase(java.util.Locale.ROOT),
        cause);
    this.reason = reason;
  }

  public Reason reason() {
    return reason;
  }
}
