package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.util.ProxyHeaderUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
final class RestClientMcpProxyTransport implements McpProxyTransportPort {

  private static final int DEFAULT_CONNECT_TIMEOUT_MS = 3000;
  private static final int DEFAULT_READ_TIMEOUT_MS = 3000;

  private final RestClient restClient;

  RestClientMcpProxyTransport(GatewayProperties properties, RestClient.Builder restClientBuilder) {
    int connectTimeoutMs =
        properties.mcp() != null ? properties.mcp().connectTimeoutMs() : DEFAULT_CONNECT_TIMEOUT_MS;
    var factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(Duration.ofMillis(connectTimeoutMs));
    factory.setReadTimeout(Duration.ofMillis(DEFAULT_READ_TIMEOUT_MS));
    this.restClient = restClientBuilder.requestFactory(factory).build();
  }

  @Override
  public void proxy(
      HttpServletRequest request, HttpServletResponse response, URI targetUrl, String tenantId)
      throws IOException {
    restClient
        .post()
        .uri(targetUrl)
        .headers(
            headers -> {
              ProxyHeaderUtils.copyRequestHeaders(request, headers);
              if (tenantId != null) {
                headers.set(IntegrationHeaders.HEADER_TENANT_ID, tenantId);
              }
              String requestId = request.getHeader(IntegrationHeaders.HEADER_REQUEST_ID);
              if (requestId != null) {
                headers.set(IntegrationHeaders.HEADER_REQUEST_ID, requestId);
              }
              String correlationId = request.getHeader(IntegrationHeaders.HEADER_CORRELATION_ID);
              if (correlationId != null) {
                headers.set(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);
              }
              headers.set(IntegrationHeaders.HEADER_SOURCE_SERVICE, "plugin-gateway");
            })
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
  }
}
