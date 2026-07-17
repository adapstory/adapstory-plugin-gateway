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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
final class RestClientMcpProxyTransport implements McpProxyTransportPort {

  private static final int DEFAULT_CONNECT_TIMEOUT_MS = 3000;
  private final RestClient restClient;

  RestClientMcpProxyTransport(
      GatewayProperties properties,
      RestClient.Builder restClientBuilder,
      @Value("${gateway.mcp.streaming-read-timeout-ms:0}") int streamingReadTimeoutMs) {
    int connectTimeoutMs =
        properties.mcp() != null ? properties.mcp().connectTimeoutMs() : DEFAULT_CONNECT_TIMEOUT_MS;
    if (streamingReadTimeoutMs < 0) {
      throw new IllegalArgumentException("MCP streaming read timeout must not be negative");
    }
    var requestFactory =
        streamingReadTimeoutMs == 0
            ? ProxyClientHttpRequestFactory.createStreaming(Duration.ofMillis(connectTimeoutMs))
            : ProxyClientHttpRequestFactory.create(
                Duration.ofMillis(connectTimeoutMs), Duration.ofMillis(streamingReadTimeoutMs));
    this.restClient = restClientBuilder.requestFactory(requestFactory).build();
  }

  @Override
  public void proxy(
      HttpServletRequest request,
      HttpServletResponse response,
      URI targetUrl,
      String tenantId,
      McpProxyResponseObserver responseObserver)
      throws IOException {
    HttpMethod method = HttpMethod.valueOf(request.getMethod());
    RestClient.RequestBodySpec upstreamRequest =
        restClient
            .method(method)
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
                  String correlationId =
                      request.getHeader(IntegrationHeaders.HEADER_CORRELATION_ID);
                  if (correlationId != null) {
                    headers.set(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);
                  }
                  headers.set(IntegrationHeaders.HEADER_SOURCE_SERVICE, "plugin-gateway");
                });
    if (HttpMethod.POST.equals(method)) {
      upstreamRequest.body(
          (StreamingHttpOutputMessage.Body)
              outputStream -> {
                try (InputStream is = request.getInputStream()) {
                  is.transferTo(outputStream);
                }
              });
    }
    upstreamRequest.exchange(
        (req, clientResponse) -> {
          responseObserver.beforeCommit(
              clientResponse.getStatusCode(), clientResponse.getHeaders(), targetUrl);
          MediaType contentType = clientResponse.getHeaders().getContentType();
          if (contentType != null && MediaType.TEXT_EVENT_STREAM.isCompatibleWith(contentType)) {
            ProxyHeaderUtils.copyStreamingResponse(
                clientResponse, response, response.getOutputStream());
          } else {
            ProxyHeaderUtils.copyResponse(clientResponse, response);
          }
          return null;
        });
  }
}
