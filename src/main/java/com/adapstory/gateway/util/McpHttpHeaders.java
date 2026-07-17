package com.adapstory.gateway.util;

/** Canonical Streamable HTTP header names and validation shared by filters and proxying. */
public final class McpHttpHeaders {

  public static final String SESSION_ID = "Mcp-Session-Id";
  public static final String PROTOCOL_VERSION = "MCP-Protocol-Version";
  public static final String LAST_EVENT_ID = "Last-Event-ID";

  private static final int MAX_SESSION_ID_LENGTH = 256;

  private McpHttpHeaders() {}

  /** MCP session identifiers are bounded visible ASCII, as required by the transport spec. */
  public static boolean isCanonicalSessionId(String value) {
    if (value == null || value.isEmpty() || value.length() > MAX_SESSION_ID_LENGTH) {
      return false;
    }
    return value.chars().allMatch(character -> character >= 0x21 && character <= 0x7e);
  }
}
