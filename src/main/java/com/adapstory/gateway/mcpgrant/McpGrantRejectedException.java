package com.adapstory.gateway.mcpgrant;

/** Typed fail-closed rejection raised while registering an MCP provider grant. */
public final class McpGrantRejectedException extends RuntimeException {

  public enum Reason {
    IDENTITY_MISMATCH,
    TOKEN_VALIDITY,
    TOKEN_ALREADY_BOUND
  }

  private final Reason reason;

  public McpGrantRejectedException(Reason reason, String message) {
    super(message);
    this.reason = reason;
  }

  public Reason reason() {
    return reason;
  }
}
