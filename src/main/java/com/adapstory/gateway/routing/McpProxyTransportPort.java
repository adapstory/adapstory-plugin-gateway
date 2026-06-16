package com.adapstory.gateway.routing;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

interface McpProxyTransportPort {

  void proxy(HttpServletRequest request, HttpServletResponse response, URI targetUrl, String tenantId)
      throws IOException;
}
