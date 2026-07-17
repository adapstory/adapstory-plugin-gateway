package com.adapstory.gateway.routing;

import java.net.URI;
import java.util.Objects;

/** Concrete provider endpoint selected for one initial or established MCP session. */
record McpSessionRoute(URI backendEndpoint, boolean newSession) {

  McpSessionRoute {
    Objects.requireNonNull(backendEndpoint, "backendEndpoint must not be null");
  }
}
