package com.adapstory.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@DisplayName("MCP grant registration body limit")
class McpGrantRegistrationBodyLimitFilterTest {

  @Test
  @DisplayName("rejects an oversized registration before Spring deserializes it")
  void should_reject_oversized_registration_body() throws Exception {
    var filter = new McpGrantRegistrationBodyLimitFilter(new ObjectMapper(), 16);
    var request = new MockHttpServletRequest("POST", "/internal/mcp-grants/v1");
    request.setContent("{\"providerBindings\":[]}".getBytes(StandardCharsets.UTF_8));
    var response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilterInternal(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(413);
    verifyNoInteractions(chain);
  }
}
