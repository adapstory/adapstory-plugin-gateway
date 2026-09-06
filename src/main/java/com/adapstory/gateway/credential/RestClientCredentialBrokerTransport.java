package com.adapstory.gateway.credential;

import com.adapstory.gateway.dto.CredentialBrokerRequest;
import com.adapstory.gateway.dto.CredentialBrokerResponse;
import java.io.IOException;
import java.util.Objects;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public final class RestClientCredentialBrokerTransport implements CredentialBrokerTransport {

  private final RestClient restClient;
  private final ObjectMapper objectMapper;

  public RestClientCredentialBrokerTransport(RestClient restClient, ObjectMapper objectMapper) {
    this.restClient = Objects.requireNonNull(restClient, "restClient must not be null");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
  }

  @Override
  public CredentialBrokerResponse forward(CredentialBrokerRequest request) {
    RestClient.RequestBodySpec outbound =
        restClient
            .method(HttpMethod.valueOf(request.httpMethod()))
            .uri(request.path())
            .contentType(MediaType.APPLICATION_JSON)
            .header("X-Credential-Assertion", request.assertion())
            .header("X-Credential-Signature", request.signature())
            .header("X-Request-Id", request.requestId());
    if (!HttpMethod.GET.matches(request.httpMethod())) {
      outbound.body(request.body());
    }
    return outbound.exchange(
        (outboundRequest, response) -> {
          try {
            byte[] responseBytes = response.getBody().readAllBytes();
            JsonNode body =
                responseBytes.length == 0
                    ? objectMapper.createObjectNode()
                    : objectMapper.readTree(responseBytes);
            return new CredentialBrokerResponse(response.getStatusCode().value(), body);
          } catch (IOException | tools.jackson.core.JacksonException exception) {
            throw new IllegalStateException("Credential Broker returned invalid JSON", exception);
          }
        });
  }
}
