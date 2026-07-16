package com.adapstory.gateway.routing;

import com.adapstory.gateway.util.ProxyHeaderUtils;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.time.Duration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/** RestClient adapter dedicated to unbounded server-sent-event responses. */
@Component
final class RestClientEventStreamProxyAdapter implements EventStreamProxyPort {

  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3);

  private final RestClient restClient;

  RestClientEventStreamProxyAdapter(RestClient.Builder restClientBuilder) {
    this.restClient =
        restClientBuilder
            .requestFactory(ProxyClientHttpRequestFactory.createStreaming(CONNECT_TIMEOUT))
            .build();
  }

  @Override
  public void stream(
      HttpHeaders requestHeaders,
      HttpServletResponse response,
      OutputStream downstreamBody,
      String targetUri)
      throws IOException {
    try {
      restClient
          .get()
          .uri(URI.create(targetUri))
          .headers(headers -> headers.addAll(requestHeaders))
          .accept(MediaType.TEXT_EVENT_STREAM)
          .exchange(
              (request, upstream) -> {
                ProxyHeaderUtils.copyStreamingResponse(upstream, response, downstreamBody);
                return null;
              });
    } catch (RestClientException ex) {
      throw new IOException("Event-stream proxy failed for target URI: " + targetUri, ex);
    }
  }
}
