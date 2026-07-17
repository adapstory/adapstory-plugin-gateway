package com.adapstory.gateway.mcpgrant;

/** Shared authorization state could not be read or written safely. */
public final class McpGrantStorageException extends RuntimeException {

  public McpGrantStorageException(String message) {
    super(message);
  }

  McpGrantStorageException(String message, Throwable cause) {
    super(message, cause);
  }
}
