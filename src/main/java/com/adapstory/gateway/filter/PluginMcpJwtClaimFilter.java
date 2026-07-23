package com.adapstory.gateway.filter;

import com.adapstory.gateway.mcpgrant.McpAccessTokenContext;
import com.adapstory.gateway.mcpgrant.McpGrantAuthorization;
import com.adapstory.gateway.mcpgrant.McpGrantService;
import com.adapstory.gateway.mcpgrant.McpGrantStorageException;
import com.adapstory.gateway.util.DelegatedAuthorityHeaders;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.adapstory.gateway.util.McpHttpHeaders;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Enforces exact route and tool bindings from the shared token-bound MCP grant. */
@Component
public final class PluginMcpJwtClaimFilter extends OncePerRequestFilter {

  public static final String MCP_TENANT_ID_ATTR = "mcpTenantId";
  public static final String MCP_PLUGIN_SLUG_ATTR = "mcpPluginSlug";
  public static final String MCP_METHOD_ATTR = "mcp.method";

  private static final Pattern MCP_PATH_PATTERN =
      Pattern.compile("^/internal/plugins/v1/([a-z](?:[a-z0-9]|-(?=[a-z0-9])){0,127})/mcp$");
  private static final String METRIC = "plugin_gateway_mcp_authorization_total";
  private static final Set<String> ROOT_FIELDS = Set.of("jsonrpc", "id", "method", "params");
  private static final Set<String> LIST_PARAM_FIELDS = Set.of("cursor", "_meta");
  private static final Set<String> CALL_PARAM_FIELDS = Set.of("name", "arguments", "_meta");
  private static final Set<String> INITIALIZE_PARAM_FIELDS =
      Set.of("protocolVersion", "capabilities", "clientInfo", "_meta");
  private static final Set<String> CANCELLATION_PARAM_FIELDS =
      Set.of("requestId", "reason", "_meta");
  private static final Set<String> META_ONLY_PARAM_FIELDS = Set.of("_meta");
  private static final Set<String> NOTIFICATION_METHODS =
      Set.of("notifications/initialized", "notifications/cancelled");
  private static final Set<String> ROUTE_SCOPED_METHODS =
      Set.of("initialize", "notifications/initialized", "notifications/cancelled", "ping");
  private static final Pattern PROTOCOL_VERSION_PATTERN =
      Pattern.compile("^[0-9]{4}-[0-9]{2}-[0-9]{2}$");

  private final ObjectMapper objectMapper;
  private final ObjectMapper strictObjectMapper;
  private final MeterRegistry meterRegistry;
  private final McpGrantService grantService;
  private final int maximumBodyBytes;

  @Autowired
  public PluginMcpJwtClaimFilter(
      ObjectMapper objectMapper,
      MeterRegistry meterRegistry,
      McpGrantService grantService,
      @Value("${gateway.mcp.grants.maximum-request-body-bytes:65536}") int maximumBodyBytes) {
    this.objectMapper = objectMapper;
    this.strictObjectMapper =
        objectMapper.copy().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    this.meterRegistry = meterRegistry;
    this.grantService = grantService;
    if (maximumBodyBytes <= 0) {
      throw new IllegalArgumentException("maximum MCP request body size must be positive");
    }
    this.maximumBodyBytes = maximumBodyBytes;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    McpAccessTokenContext token =
        (McpAccessTokenContext)
            request.getAttribute(McpGrantJwtAuthenticationFilter.MCP_ACCESS_TOKEN_ATTR);
    if (token == null) {
      deny(response, request, 401, "Unauthorized", "Authentication required", "missing_token");
      return;
    }
    String slug = extractSlug(request.getRequestURI());
    if (slug == null) {
      deny(response, request, 400, "Bad Request", "Invalid MCP route", "invalid_route");
      return;
    }
    if (request.getHeader("Origin") != null) {
      deny(response, request, 403, "Forbidden", "Origin is not allowed", "origin_not_allowed");
      return;
    }

    McpGrantAuthorization authorization;
    try {
      Optional<McpGrantAuthorization> stored = grantService.findAuthorization(token);
      if (stored.isEmpty()) {
        deny(
            response,
            request,
            403,
            "Forbidden",
            "MCP grant is missing or expired",
            "missing_grant");
        return;
      }
      authorization = stored.get();
    } catch (McpGrantStorageException exception) {
      deny(
          response,
          request,
          503,
          "Service Unavailable",
          "Shared MCP authorization is unavailable",
          "store_unavailable");
      return;
    }

    String httpMethod = request.getMethod();
    if ("GET".equals(httpMethod) || "DELETE".equals(httpMethod)) {
      authorizeSessionTransportRequest(
          request, response, filterChain, authorization, slug, httpMethod);
      return;
    }
    if (!"POST".equals(httpMethod)) {
      deny(
          response,
          request,
          405,
          "Method Not Allowed",
          "Unsupported MCP HTTP method",
          "http_method_not_allowed");
      return;
    }

    byte[] body = request.getInputStream().readNBytes(maximumBodyBytes + 1);
    if (body.length > maximumBodyBytes) {
      deny(
          response,
          request,
          413,
          "Payload Too Large",
          "MCP request body is too large",
          "body_too_large");
      return;
    }
    JsonNode root;
    try {
      root = strictObjectMapper.readTree(body);
    } catch (IOException exception) {
      deny(response, request, 400, "Bad Request", "Invalid MCP JSON-RPC body", "invalid_body");
      return;
    }
    if (root == null
        || !root.isObject()
        || !hasOnlyFields(root, ROOT_FIELDS)
        || !"2.0".equals(root.path("jsonrpc").asText(null))
        || !root.path("method").isTextual()) {
      deny(response, request, 400, "Bad Request", "Invalid MCP JSON-RPC body", "invalid_body");
      return;
    }

    String method = root.path("method").textValue();
    if (!hasCanonicalEnvelope(root, method) || !hasCanonicalParams(method, root.path("params"))) {
      deny(response, request, 400, "Bad Request", "Invalid MCP JSON-RPC body", "invalid_body");
      return;
    }
    String sessionReason = validatePostSession(request, method);
    if (sessionReason != null) {
      deny(response, request, 400, "Bad Request", "Invalid MCP session headers", sessionReason);
      return;
    }
    String reason = authorizationReason(authorization, slug, method, root.path("params"));
    if (reason != null) {
      deny(response, request, 403, "Forbidden", "MCP operation is not bound to this grant", reason);
      return;
    }

    setAllowedAttributes(request, authorization, slug, method);
    byte[] canonicalBody = objectMapper.writeValueAsBytes(root);
    if (canonicalBody.length > maximumBodyBytes) {
      deny(
          response,
          request,
          413,
          "Payload Too Large",
          "MCP request body is too large",
          "body_too_large");
      return;
    }
    filterChain.doFilter(new ReplayableBodyServletWrapper(request, canonicalBody), response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return extractSlug(request.getRequestURI()) == null;
  }

  static String extractSlug(String path) {
    Matcher matcher = MCP_PATH_PATTERN.matcher(path);
    return matcher.matches() ? matcher.group(1) : null;
  }

  private static String authorizationReason(
      McpGrantAuthorization authorization, String slug, String method, JsonNode params) {
    if (ROUTE_SCOPED_METHODS.contains(method)) {
      return authorization.allowsToolList(slug) ? null : "route_not_bound";
    }
    if ("tools/list".equals(method)) {
      return authorization.allowsToolList(slug) ? null : "route_not_bound";
    }
    if (!"tools/call".equals(method)) {
      return "method_not_allowed";
    }
    if (!params.isObject() || !params.path("name").isTextual()) {
      return "invalid_tool_call";
    }
    return authorization.allowsToolCall(slug, params.path("name").textValue())
        ? null
        : "tool_not_bound";
  }

  private static boolean hasCanonicalParams(String method, JsonNode params) {
    if ("initialize".equals(method)) {
      return params.isObject()
          && hasOnlyFields(params, INITIALIZE_PARAM_FIELDS)
          && params.path("protocolVersion").isTextual()
          && PROTOCOL_VERSION_PATTERN.matcher(params.path("protocolVersion").textValue()).matches()
          && params.path("capabilities").isObject()
          && params.path("clientInfo").isObject()
          && (!params.has("_meta") || params.path("_meta").isObject());
    }
    if ("notifications/cancelled".equals(method)) {
      return params.isObject()
          && hasOnlyFields(params, CANCELLATION_PARAM_FIELDS)
          && hasCanonicalId(params.path("requestId"))
          && (!params.has("reason") || params.path("reason").isTextual())
          && (!params.has("_meta") || params.path("_meta").isObject());
    }
    if (ROUTE_SCOPED_METHODS.contains(method)) {
      return params.isMissingNode()
          || params.isNull()
          || (params.isObject()
              && hasOnlyFields(params, META_ONLY_PARAM_FIELDS)
              && (!params.has("_meta") || params.path("_meta").isObject()));
    }
    if ("tools/list".equals(method)) {
      return params.isMissingNode()
          || params.isNull()
          || (params.isObject()
              && hasOnlyFields(params, LIST_PARAM_FIELDS)
              && (!params.has("cursor") || params.path("cursor").isTextual())
              && (!params.has("_meta") || params.path("_meta").isObject()));
    }
    if (!"tools/call".equals(method)) {
      return true;
    }
    return params.isObject()
        && hasOnlyFields(params, CALL_PARAM_FIELDS)
        && params.path("name").isTextual()
        && (!params.has("arguments") || params.path("arguments").isObject())
        && (!params.has("_meta") || params.path("_meta").isObject());
  }

  private static boolean hasCanonicalEnvelope(JsonNode root, String method) {
    if (NOTIFICATION_METHODS.contains(method)) {
      return !root.has("id");
    }
    return root.has("id") && hasCanonicalId(root.path("id"));
  }

  private static boolean hasCanonicalId(JsonNode id) {
    if (id.isIntegralNumber()) {
      return true;
    }
    if (!id.isTextual()) {
      return false;
    }
    String value = id.textValue();
    return !value.isBlank()
        && value.length() <= 256
        && value.chars().noneMatch(Character::isISOControl);
  }

  private static boolean hasOnlyFields(JsonNode node, Set<String> allowed) {
    var names = node.fieldNames();
    while (names.hasNext()) {
      if (!allowed.contains(names.next())) {
        return false;
      }
    }
    return true;
  }

  private void authorizeSessionTransportRequest(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain,
      McpGrantAuthorization authorization,
      String slug,
      String httpMethod)
      throws IOException, ServletException {
    String sessionReason = validateEstablishedSessionHeaders(request);
    if (sessionReason != null) {
      deny(response, request, 400, "Bad Request", "Invalid MCP session headers", sessionReason);
      return;
    }
    if ("GET".equals(httpMethod) && !request.getHeaders("Accept").asIterator().hasNext()) {
      deny(
          response,
          request,
          406,
          "Not Acceptable",
          "SSE Accept header is required",
          "accept_required");
      return;
    }
    if ("GET".equals(httpMethod)
        && request.getHeaders("Accept").asIterator().hasNext()
        && java.util.Collections.list(request.getHeaders("Accept")).stream()
            .noneMatch(value -> value.contains("text/event-stream"))) {
      deny(
          response,
          request,
          406,
          "Not Acceptable",
          "SSE Accept header is required",
          "accept_required");
      return;
    }
    if (!authorization.allowsToolList(slug)) {
      deny(
          response,
          request,
          403,
          "Forbidden",
          "MCP operation is not bound to this grant",
          "route_not_bound");
      return;
    }
    String method = "GET".equals(httpMethod) ? "stream/get" : "session/delete";
    setAllowedAttributes(request, authorization, slug, method);
    filterChain.doFilter(request, response);
  }

  private static String validatePostSession(HttpServletRequest request, String method) {
    String sessionId = request.getHeader(McpHttpHeaders.SESSION_ID);
    if ("initialize".equals(method)) {
      return sessionId == null ? null : "initialize_with_session";
    }
    return validateEstablishedSessionHeaders(request);
  }

  private static String validateEstablishedSessionHeaders(HttpServletRequest request) {
    if (!McpHttpHeaders.isCanonicalSessionId(request.getHeader(McpHttpHeaders.SESSION_ID))) {
      return "session_required";
    }
    String protocolVersion = request.getHeader(McpHttpHeaders.PROTOCOL_VERSION);
    if (protocolVersion == null || !PROTOCOL_VERSION_PATTERN.matcher(protocolVersion).matches()) {
      return "protocol_version_required";
    }
    return null;
  }

  private void setAllowedAttributes(
      HttpServletRequest request, McpGrantAuthorization authorization, String slug, String method) {
    request.setAttribute(MCP_TENANT_ID_ATTR, authorization.tenantId());
    request.setAttribute(MCP_PLUGIN_SLUG_ATTR, slug);
    request.setAttribute(MCP_METHOD_ATTR, method);
    if (authorization.delegatedAuthority() != null) {
      var delegated = authorization.delegatedAuthority();
      request.setAttribute(
          DelegatedAuthorityHeaders.TRUSTED_RUN_ID_ATTR, delegated.runId().toString());
      request.setAttribute(DelegatedAuthorityHeaders.TRUSTED_NODE_ID_ATTR, delegated.nodeId());
      request.setAttribute(
          DelegatedAuthorityHeaders.TRUSTED_POLICY_VERSION_ATTR, delegated.policyVersion());
      request.setAttribute(
          DelegatedAuthorityHeaders.TRUSTED_GRANT_ID_ATTR, delegated.grantId().toString());
      request.setAttribute(
          DelegatedAuthorityHeaders.TRUSTED_CAPABILITIES_ATTR,
          String.join(" ", authorization.capabilitiesForRoute(slug)));
    }
    meterRegistry
        .counter(METRIC, "outcome", "allowed", "reason", method.replace('/', '_'))
        .increment();
  }

  private void deny(
      HttpServletResponse response,
      HttpServletRequest request,
      int status,
      String error,
      String message,
      String reason)
      throws IOException {
    meterRegistry.counter(METRIC, "outcome", "denied", "reason", reason).increment();
    GatewayErrorWriter.writeError(
        objectMapper, response, request, status, error, message, Map.of("reason", reason));
  }
}
