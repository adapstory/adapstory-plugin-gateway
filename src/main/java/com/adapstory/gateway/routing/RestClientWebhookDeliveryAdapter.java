package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import java.net.URI;
import java.time.Duration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@Component
final class RestClientWebhookDeliveryAdapter implements WebhookDeliveryPort {

  private static final int CONNECT_TIMEOUT_MS = 3000;
  private static final int READ_TIMEOUT_MS = 3000;

  private final RestClient restClient;

  RestClientWebhookDeliveryAdapter(RestClient.Builder restClientBuilder) {
    var factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS));
    factory.setReadTimeout(Duration.ofMillis(READ_TIMEOUT_MS));
    this.restClient = restClientBuilder.requestFactory(factory).build();
  }

  @Override
  public void send(String pluginPodUrl, byte[] payload, HttpHeaders headers) {
    restClient
        .post()
        .uri(URI.create(pluginPodUrl))
        .headers(
            targetHeaders -> {
              if (headers.getContentType() != null) {
                targetHeaders.setContentType(headers.getContentType());
              } else {
                targetHeaders.setContentType(MediaType.APPLICATION_JSON);
              }
              String correlationId = headers.getFirst(IntegrationHeaders.HEADER_CORRELATION_ID);
              if (correlationId != null) {
                targetHeaders.set(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);
              }
            })
        .body(payload)
        .retrieve()
        .toBodilessEntity();
  }
}
