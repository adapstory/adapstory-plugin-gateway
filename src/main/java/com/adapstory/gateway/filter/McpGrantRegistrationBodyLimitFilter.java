package com.adapstory.gateway.filter;

import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Caps grant JSON before Spring/Jackson can allocate an unbounded request object. */
@Component
public final class McpGrantRegistrationBodyLimitFilter extends OncePerRequestFilter {

  private static final String GRANT_PATH = "/internal/mcp-grants/v1";

  private final ObjectMapper objectMapper;
  private final int maximumBodyBytes;

  public McpGrantRegistrationBodyLimitFilter(
      ObjectMapper objectMapper,
      @Value("${gateway.mcp.grants.maximum-registration-body-bytes:65536}") int maximumBodyBytes) {
    this.objectMapper = objectMapper;
    if (maximumBodyBytes <= 0) {
      throw new IllegalArgumentException("maximum MCP grant body size must be positive");
    }
    this.maximumBodyBytes = maximumBodyBytes;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    long declaredLength = request.getContentLengthLong();
    if (declaredLength > maximumBodyBytes) {
      reject(request, response);
      return;
    }
    byte[] body = request.getInputStream().readNBytes(maximumBodyBytes + 1);
    if (body.length > maximumBodyBytes) {
      reject(request, response);
      return;
    }
    filterChain.doFilter(new ReplayableBodyServletWrapper(request, body), response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !GRANT_PATH.equals(request.getRequestURI());
  }

  private void reject(HttpServletRequest request, HttpServletResponse response) throws IOException {
    GatewayErrorWriter.writeError(
        objectMapper,
        response,
        request,
        413,
        "Payload Too Large",
        "MCP grant registration body is too large",
        Map.of("reason", "body_too_large"));
  }
}
