package com.adapstory.gateway.routing;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Enumeration;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.http.client.ClientHttpResponse;
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

  private static final Set<String> HOP_BY_HOP_HEADERS =
      Set.of(
          "connection",
          "content-length",
          "keep-alive",
          "proxy-authenticate",
          "proxy-authorization",
          "te",
          "trailers",
          "transfer-encoding",
          "upgrade",
          "host");

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
          .headers(headers -> copyRequestHeaders(request, headers))
          .body(
              (StreamingHttpOutputMessage.Body)
                  outputStream -> {
                    try (InputStream is = request.getInputStream()) {
                      is.transferTo(outputStream);
                    }
                  })
          .exchange(
              (req, clientResponse) -> {
                copyResponse(clientResponse, response);
                return null;
              });
    } else {
      restClient
          .method(method)
          .uri(URI.create(targetUri))
          .headers(headers -> copyRequestHeaders(request, headers))
          .exchange(
              (req, clientResponse) -> {
                copyResponse(clientResponse, response);
                return null;
              });
    }
  }

  /**
   * Copies safe request headers from the incoming servlet request to the outgoing {@link
   * HttpHeaders}, skipping hop-by-hop headers and Authorization.
   *
   * @param request incoming servlet request
   * @param headers outgoing REST client headers
   */
  public void copyRequestHeaders(HttpServletRequest request, HttpHeaders headers) {
    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      if (HOP_BY_HOP_HEADERS.contains(headerName.toLowerCase())) {
        continue;
      }
      if (headerName.equalsIgnoreCase(HttpHeaders.AUTHORIZATION)) {
        continue; // Don't forward plugin JWT to target BC
      }
      Enumeration<String> values = request.getHeaders(headerName);
      while (values.hasMoreElements()) {
        headers.add(headerName, values.nextElement());
      }
    }
  }

  /**
   * Copies the response from the upstream client response to the servlet response, including status
   * code, headers (excluding hop-by-hop), and body.
   *
   * @param clientResponse upstream response
   * @param response downstream servlet response
   * @throws IOException if an I/O error occurs during body transfer
   */
  public void copyResponse(ClientHttpResponse clientResponse, HttpServletResponse response)
      throws IOException {
    response.setStatus(clientResponse.getStatusCode().value());

    clientResponse
        .getHeaders()
        .forEach(
            (name, values) -> {
              if (!HOP_BY_HOP_HEADERS.contains(name.toLowerCase())) {
                for (String value : values) {
                  response.addHeader(name, value);
                }
              }
            });

    try (InputStream body = clientResponse.getBody()) {
      body.transferTo(response.getOutputStream());
    }
  }
}
