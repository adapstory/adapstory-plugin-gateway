package com.adapstory.gateway.routing;

import com.adapstory.gateway.util.ProxyHeaderUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import org.springframework.http.HttpMethod;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

@Component
final class RestClientProxyExecutionAdapter implements ProxyExecutionPort {

  private static final int CONNECT_TIMEOUT_MS = 3000;
  private static final int READ_TIMEOUT_MS = 3000;

  private final RestClient restClient;

  RestClientProxyExecutionAdapter(RestClient.Builder restClientBuilder) {
    this(
        restClientBuilder,
        Duration.ofMillis(CONNECT_TIMEOUT_MS),
        Duration.ofMillis(READ_TIMEOUT_MS));
  }

  RestClientProxyExecutionAdapter(
      RestClient.Builder restClientBuilder, Duration connectTimeout, Duration readTimeout) {
    this.restClient =
        restClientBuilder
            .requestFactory(ProxyClientHttpRequestFactory.create(connectTimeout, readTimeout))
            .build();
  }

  @Override
  public void execute(HttpServletRequest request, HttpServletResponse response, String targetUri)
      throws IOException {
    HttpMethod method = HttpMethod.valueOf(request.getMethod());
    boolean hasBody =
        method == HttpMethod.POST || method == HttpMethod.PUT || method == HttpMethod.PATCH;

    try {
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
        return;
      }

      restClient
          .method(method)
          .uri(URI.create(targetUri))
          .headers(headers -> ProxyHeaderUtils.copyRequestHeaders(request, headers))
          .exchange(
              (req, clientResponse) -> {
                ProxyHeaderUtils.copyResponse(clientResponse, response);
                return null;
              });
    } catch (ResourceAccessException ex) {
      throw new IOException("Proxy request failed for target URI: " + targetUri, ex);
    }
  }
}
