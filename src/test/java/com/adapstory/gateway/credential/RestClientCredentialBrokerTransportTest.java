package com.adapstory.gateway.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.adapstory.gateway.dto.CredentialBrokerRequest;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

class RestClientCredentialBrokerTransportTest {

  private MockRestServiceServer server;
  private RestClientCredentialBrokerTransport transport;

  @BeforeEach
  void setUp() {
    RestClient.Builder builder = RestClient.builder().baseUrl("https://broker.example");
    server = MockRestServiceServer.bindTo(builder).build();
    transport =
        new RestClientCredentialBrokerTransport(builder.build(), JsonMapper.builder().build());
  }

  @Test
  void preservesAssertionHeadersAndValidBrokerResponse() {
    server
        .expect(requestTo("https://broker.example/credentials"))
        .andExpect(header("X-Credential-Assertion", "assertion"))
        .andExpect(header("X-Credential-Signature", "signature"))
        .andExpect(header("X-Request-Id", "request-id"))
        .andRespond(withSuccess("{\"ok\":true}", MediaType.APPLICATION_JSON));

    var response = transport.forward(request());

    assertThat(response.body().path("ok").asBoolean()).isTrue();
    server.verify();
  }

  @Test
  void translatesMalformedBrokerJsonToTransportFailure() {
    server
        .expect(requestTo("https://broker.example/credentials"))
        .andRespond(withSuccess("{", MediaType.APPLICATION_JSON));

    assertThatThrownBy(() -> transport.forward(request()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("Credential Broker returned invalid JSON")
        .hasCauseInstanceOf(JacksonException.class);
    server.verify();
  }

  @Test
  void preservesResponseReadFailureHandling() {
    InputStream brokenBody =
        new InputStream() {
          @Override
          public int read() throws IOException {
            throw new IOException("response stream failed");
          }
        };
    server
        .expect(requestTo("https://broker.example/credentials"))
        .andRespond(request -> new MockClientHttpResponse(brokenBody, HttpStatus.OK));

    assertThatThrownBy(() -> transport.forward(request()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("Credential Broker returned invalid JSON")
        .hasCauseInstanceOf(IOException.class);
    server.verify();
  }

  private static CredentialBrokerRequest request() {
    return new CredentialBrokerRequest(
        "GET", "/credentials", null, "assertion", "signature", "request-id");
  }
}
