package com.adapstory.gateway.routing;

import com.adapstory.gateway.util.ProxyHeaderUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

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

  private static final Logger log = LoggerFactory.getLogger(ProxyExecutionService.class);

  private final RestClient restClient;

  public ProxyExecutionService(RestClient.Builder restClientBuilder) {
    this.restClient = restClientBuilder.build();
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
    HttpMethod method = HttpMethod.valueOf(request.getMethod());
    boolean hasBody =
        method == HttpMethod.POST || method == HttpMethod.PUT || method == HttpMethod.PATCH;

    if (hasBody) {
      restClient
          .method(method)
          .uri(URI.create(targetUri))
          .headers(headers -> ProxyHeaderUtils.copyRequestHeaders(request, headers))
          .body(
              (StreamingHttpOutputMessage.Body)
                  outputStream -> {
                    try (InputStream is = request.getInputStream()) {
                      is.transferTo(outputStream);
                    }
                  })
          .exchange(
              (req, clientResponse) -> {
                ProxyHeaderUtils.copyResponse(clientResponse, response);
                return null;
              });
    } else {
      restClient
          .method(method)
          .uri(URI.create(targetUri))
          .headers(headers -> ProxyHeaderUtils.copyRequestHeaders(request, headers))
          .exchange(
              (req, clientResponse) -> {
                ProxyHeaderUtils.copyResponse(clientResponse, response);
                return null;
              });
    }
  }
}
