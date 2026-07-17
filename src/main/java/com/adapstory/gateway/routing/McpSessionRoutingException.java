package com.adapstory.gateway.routing;

/** Sanitized fail-closed outcome from shared stateful MCP backend routing. */
final class McpSessionRoutingException extends RuntimeException {

  enum Reason {
    SESSION_NOT_FOUND,
    AFFINITY_UNAVAILABLE,
    INVALID_SESSION
  }

  private final Reason reason;

  McpSessionRoutingException(Reason reason) {
    super("MCP session routing failed: " + reason.name().toLowerCase(java.util.Locale.ROOT));
    this.reason = reason;
  }

  McpSessionRoutingException(Reason reason, Throwable cause) {
    super("MCP session routing failed: " + reason.name().toLowerCase(java.util.Locale.ROOT), cause);
    this.reason = reason;
  }

  Reason reason() {
    return reason;
  }

  int httpStatus() {
    return switch (reason) {
      case SESSION_NOT_FOUND -> 404;
      case INVALID_SESSION -> 400;
      case AFFINITY_UNAVAILABLE -> 503;
    };
  }
}
