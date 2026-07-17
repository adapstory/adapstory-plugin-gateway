package com.adapstory.gateway.routing;

/** Raised when shared MCP session routing state cannot be read or changed safely. */
final class McpSessionAffinityStoreException extends RuntimeException {

  McpSessionAffinityStoreException(String message, Throwable cause) {
    super(message, cause);
  }

  McpSessionAffinityStoreException(String message) {
    super(message);
  }
}
