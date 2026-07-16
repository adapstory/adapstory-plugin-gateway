package com.adapstory.gateway.routing;

import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;

final class ProxyClientHttpRequestFactory {

  private ProxyClientHttpRequestFactory() {}

  static ClientHttpRequestFactory create(Duration connectTimeout, Duration readTimeout) {
    var factory = createJdkFactory(connectTimeout);
    factory.setReadTimeout(readTimeout);
    return factory;
  }

  /** Creates a connection-bounded client with no response-duration cap for SSE. */
  static ClientHttpRequestFactory createStreaming(Duration connectTimeout) {
    return createJdkFactory(connectTimeout);
  }

  private static JdkClientHttpRequestFactory createJdkFactory(Duration connectTimeout) {
    var httpClient =
        HttpClient.newBuilder()
            .connectTimeout(connectTimeout)
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    return new JdkClientHttpRequestFactory(httpClient);
  }
}
