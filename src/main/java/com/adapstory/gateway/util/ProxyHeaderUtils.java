package com.adapstory.gateway.util;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.filter.HeaderInjectionFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Locale;
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

  private static final Set<String> CALLER_CONTROLLED_SECURITY_HEADERS =
      Set.of(
          HttpHeaders.AUTHORIZATION.toLowerCase(Locale.ROOT),
          HttpHeaders.COOKIE.toLowerCase(Locale.ROOT),
          HttpHeaders.ORIGIN.toLowerCase(Locale.ROOT),
          IntegrationHeaders.HEADER_TENANT_ID.toLowerCase(Locale.ROOT),
          IntegrationHeaders.HEADER_USER_ID.toLowerCase(Locale.ROOT),
          IntegrationHeaders.HEADER_ADAPSTORY_USER_ID.toLowerCase(Locale.ROOT),
          HeaderInjectionFilter.HEADER_USER_ROLES.toLowerCase(Locale.ROOT));

  private static final Set<String> SAFE_RESPONSE_HEADERS =
      Set.of(
          HttpHeaders.CONTENT_TYPE.toLowerCase(Locale.ROOT),
          HttpHeaders.CACHE_CONTROL.toLowerCase(Locale.ROOT),
          HttpHeaders.ETAG.toLowerCase(Locale.ROOT),
          HttpHeaders.LAST_MODIFIED.toLowerCase(Locale.ROOT),
          HttpHeaders.CONTENT_DISPOSITION.toLowerCase(Locale.ROOT),
          HttpHeaders.LOCATION.toLowerCase(Locale.ROOT),
          HttpHeaders.RETRY_AFTER.toLowerCase(Locale.ROOT),
          HttpHeaders.EXPIRES.toLowerCase(Locale.ROOT),
          HttpHeaders.ACCEPT_RANGES.toLowerCase(Locale.ROOT),
          HttpHeaders.CONTENT_RANGE.toLowerCase(Locale.ROOT),
          IntegrationHeaders.HEADER_REQUEST_ID.toLowerCase(Locale.ROOT),
          IntegrationHeaders.HEADER_RESPONSE_ID.toLowerCase(Locale.ROOT),
          IntegrationHeaders.HEADER_CORRELATION_ID.toLowerCase(Locale.ROOT),
          "x-accel-buffering");

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
      String normalizedHeaderName = headerName.toLowerCase(Locale.ROOT);
      if (HOP_BY_HOP_HEADERS.contains(normalizedHeaderName)
          || CALLER_CONTROLLED_SECURITY_HEADERS.contains(normalizedHeaderName)) {
        continue;
      }
      Enumeration<String> values = request.getHeaders(headerName);
      while (values.hasMoreElements()) {
        headers.add(headerName, values.nextElement());
      }
    }
    copyTrustedIdentity(
        request,
        headers,
        IntegrationHeaders.HEADER_TENANT_ID,
        HeaderInjectionFilter.TRUSTED_TENANT_ID_ATTR);
    copyTrustedIdentity(
        request,
        headers,
        IntegrationHeaders.HEADER_USER_ID,
        HeaderInjectionFilter.TRUSTED_USER_ID_ATTR);
    copyTrustedIdentity(
        request,
        headers,
        IntegrationHeaders.HEADER_ADAPSTORY_USER_ID,
        HeaderInjectionFilter.TRUSTED_ADAPSTORY_USER_ID_ATTR);
    copyTrustedIdentity(
        request,
        headers,
        HeaderInjectionFilter.HEADER_USER_ROLES,
        HeaderInjectionFilter.TRUSTED_USER_ROLES_ATTR);
  }

  private static void copyTrustedIdentity(
      HttpServletRequest request, HttpHeaders headers, String headerName, String attributeName) {
    Object value = request.getAttribute(attributeName);
    if (value instanceof String trustedValue && !trustedValue.isBlank()) {
      headers.set(headerName, trustedValue);
    }
  }

  /**
   * Copies the response from the upstream client response to the servlet response, including status
   * code, allow-listed representation and tracing headers, and body.
   *
   * @param clientResponse upstream response
   * @param response downstream servlet response
   * @throws IOException if an I/O error occurs during body transfer
   */
  public static void copyResponse(ClientHttpResponse clientResponse, HttpServletResponse response)
      throws IOException {
    copyResponseMetadata(clientResponse, response);
    try (InputStream body = clientResponse.getBody()) {
      body.transferTo(response.getOutputStream());
    }
  }

  /**
   * Copies and flushes a streaming response chunk-by-chunk.
   *
   * <p>{@link InputStream#transferTo(OutputStream)} may leave small SSE frames buffered until the
   * upstream closes. Explicit flushing makes each completed event visible to the browser while the
   * generation run is still active.
   */
  public static void copyStreamingResponse(
      ClientHttpResponse clientResponse, HttpServletResponse response, OutputStream downstreamBody)
      throws IOException {
    copyResponseMetadata(clientResponse, response);
    byte[] buffer = new byte[8192];
    try (InputStream body = clientResponse.getBody()) {
      int bytesRead;
      while ((bytesRead = body.read(buffer)) != -1) {
        downstreamBody.write(buffer, 0, bytesRead);
        downstreamBody.flush();
      }
    }
  }

  private static void copyResponseMetadata(
      ClientHttpResponse clientResponse, HttpServletResponse response) throws IOException {
    response.setStatus(clientResponse.getStatusCode().value());
    clientResponse
        .getHeaders()
        .forEach(
            (name, values) -> {
              if (SAFE_RESPONSE_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                for (String value : values) {
                  response.addHeader(name, value);
                }
              }
            });
  }
}
