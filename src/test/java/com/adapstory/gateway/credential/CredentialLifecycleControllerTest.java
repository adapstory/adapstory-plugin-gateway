package com.adapstory.gateway.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.adapstory.gateway.dto.CredentialBrokerResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

@DisplayName("Credential lifecycle command ingress")
class CredentialLifecycleControllerTest {

  private static final String COMMAND_KEY = "550e8400-e29b-41d4-a716-446655440000";

  private final CredentialLifecycleForwarder forwarder = mock(CredentialLifecycleForwarder.class);
  private final CredentialLifecycleController controller =
      new CredentialLifecycleController(
          forwarder, mock(CredentialHumanApprovalForwarder.class), JsonMapper.builder().build());
  private final ObjectMapper mapper = JsonMapper.builder().build();

  @Test
  @DisplayName("plan and containment forward the same canonical key bound to their bodies")
  void shouldForwardMatchingPlanAndContainmentKeys() throws Exception {
    JsonNode plan = mapper.readTree("{\"idempotency_key\":\"" + COMMAND_KEY + "\"}");
    JsonNode containment = mapper.readTree("{\"idempotency_key\":\"" + COMMAND_KEY + "\"}");
    MockHttpServletRequest request = request();
    when(forwarder.forward(
            eq(CredentialCapability.PLAN), anyString(), anyString(), same(plan), any()))
        .thenReturn(new CredentialBrokerResponse(201, plan));
    when(forwarder.forward(
            eq(CredentialCapability.CONTAIN), anyString(), anyString(), same(containment), any()))
        .thenReturn(new CredentialBrokerResponse(202, containment));

    assertThat(controller.plan(plan, COMMAND_KEY, request).getStatusCode().value()).isEqualTo(201);
    assertThat(controller.contain(containment, COMMAND_KEY, request).getStatusCode().value())
        .isEqualTo(202);
  }

  @Test
  @DisplayName("rejects absent, malformed, and conflicting keys before broker forwarding")
  void shouldRejectInvalidCommandKeys() throws Exception {
    JsonNode matching = mapper.readTree("{\"idempotency_key\":\"" + COMMAND_KEY + "\"}");
    JsonNode conflicting =
        mapper.readTree("{\"idempotency_key\":\"550e8400-e29b-41d4-a716-446655440001\"}");
    MockHttpServletRequest request = request();

    assertThatThrownBy(() -> controller.plan(matching, null, request))
        .isInstanceOf(ResponseStatusException.class);
    assertThatThrownBy(() -> controller.contain(matching, "not-a-uuid", request))
        .isInstanceOf(ResponseStatusException.class);
    assertThatThrownBy(() -> controller.plan(conflicting, COMMAND_KEY, request))
        .isInstanceOf(ResponseStatusException.class);
    request.addHeader("X-Idempotency-Key", COMMAND_KEY);
    assertThatThrownBy(() -> controller.plan(matching, COMMAND_KEY, request))
        .isInstanceOf(ResponseStatusException.class);
    verifyNoInteractions(forwarder);
  }

  private static MockHttpServletRequest request() {
    var request = new MockHttpServletRequest();
    request.addHeader("X-Credential-Task-Attestation", "attestation");
    request.addHeader("X-Credential-Task-Signature", "signature");
    request.addHeader("X-Request-Id", "request-1234");
    request.addHeader("X-Idempotency-Key", COMMAND_KEY);
    return request;
  }
}
