package com.adapstory.gateway.routing;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Service;

/**
 * Service for executing proxy requests to backend services.
 *
 * <p>Extracted from {@code PluginRouteResolver} (P3-22) to isolate proxy execution mechanics from
 * route resolution, improving testability and SRP adherence.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Execute HTTP proxy requests with body streaming for POST/PUT/PATCH
 *   <li>Copy safe request headers (excluding hop-by-hop and Authorization)
 *   <li>Copy upstream response status, headers, and body to downstream response
 * </ul>
 */
@Service
public class ProxyExecutionService {

  private final ProxyExecutionPort proxyExecutionPort;

  public ProxyExecutionService(ProxyExecutionPort proxyExecutionPort) {
    this.proxyExecutionPort = proxyExecutionPort;
  }

  /**
   * Executes a proxy request to the target URI, streaming request body for methods that have a body
   * (POST, PUT, PATCH) and copying the upstream response back.
   *
   * @param request incoming servlet request
   * @param response outgoing servlet response
   * @param targetUri fully resolved target URI
   * @throws IOException if an I/O error occurs during proxying
   */
  public void executeProxy(
      HttpServletRequest request, HttpServletResponse response, String targetUri)
      throws IOException {
    proxyExecutionPort.execute(request, response, targetUri);
  }
}
