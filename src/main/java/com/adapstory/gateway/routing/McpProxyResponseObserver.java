package com.adapstory.gateway.routing;

import java.net.URI;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;

/** Runs before an upstream MCP response is committed to the downstream client. */
@FunctionalInterface
interface McpProxyResponseObserver {

  void beforeCommit(HttpStatusCode status, HttpHeaders headers, URI backendEndpoint);
}
