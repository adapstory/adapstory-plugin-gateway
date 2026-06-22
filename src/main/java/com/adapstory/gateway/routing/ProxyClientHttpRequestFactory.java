package com.adapstory.gateway.routing;

import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;

final class ProxyClientHttpRequestFactory {

  private ProxyClientHttpRequestFactory() {}

  static ClientHttpRequestFactory create(Duration connectTimeout, Duration readTimeout) {
    var httpClient =
        HttpClient.newBuilder()
            .connectTimeout(connectTimeout)
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    var factory = new JdkClientHttpRequestFactory(httpClient);
    factory.setReadTimeout(readTimeout);
    return factory;
  }
}
