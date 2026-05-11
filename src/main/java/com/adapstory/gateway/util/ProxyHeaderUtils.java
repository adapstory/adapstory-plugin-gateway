package com.adapstory.gateway.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Set;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Shared proxy header utilities.
 *
 * <p>Eliminates duplication of hop-by-hop header filtering and safe header copying between {@code
 * McpProxyService} and {@code ProxyExecutionService} (SOLID audit finding #4).
 */
public final class ProxyHeaderUtils {

  /** HTTP hop-by-hop headers that must not be forwarded between proxy legs. */
  public static final Set<String> HOP_BY_HOP_HEADERS =
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

  private ProxyHeaderUtils() {}

  /**
   * Copies safe request headers from the incoming servlet request to the outgoing {@link
   * HttpHeaders}, skipping hop-by-hop headers and Authorization.
   *
   * @param request incoming servlet request
   * @param headers outgoing REST client headers
   */
  public static void copyRequestHeaders(HttpServletRequest request, HttpHeaders headers) {
    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      if (HOP_BY_HOP_HEADERS.contains(headerName.toLowerCase())) {
        continue;
      }
      if (headerName.equalsIgnoreCase(HttpHeaders.AUTHORIZATION)) {
        continue;
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
  public static void copyResponse(ClientHttpResponse clientResponse, HttpServletResponse response)
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
