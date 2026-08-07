package com.adapstory.gateway.routing;

import com.adapstory.gateway.util.ProxyHeaderUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

/** Dedicated non-buffering route for AI course-generation live-preview events. */
@PermitAll
@RestController
public class FirstPartyPluginEventStreamRouteController {

  private static final String PLUGIN_SLUG = "ai-course-generator";
  private static final String CACHE_CONTROL = "no-cache, no-transform";

  private final McpProxyService mcpProxyService;
  private final EventStreamProxyPort proxy;

  FirstPartyPluginEventStreamRouteController(
      McpProxyService mcpProxyService, EventStreamProxyPort proxy) {
    this.mcpProxyService = mcpProxyService;
    this.proxy = proxy;
  }

  /**
   * Streams replayable lesson events without the ordinary REST response buffer or circuit breaker.
   *
   * <p>The UUID path type rejects malformed run identifiers before any upstream call. Tenant and
   * identity headers have already been established by the gateway auth filter and are copied using
   * the same allow-list rules as ordinary first-party proxy traffic.
   */
  @GetMapping(
      path = "/api/plugins/ai-course-generator/v1/runs/{runId}/events",
      produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  @Operation(
      summary = "Stream AI course-generation run events",
      description =
          "Streams replayable server-sent events for one immutable course-generation run.")
  @ApiResponse(
      responseCode = "200",
      description = "Replayable course-generation event stream",
      content = @Content(schema = @Schema(type = "string", description = "SSE event stream")))
  public StreamingResponseBody stream(
      @Parameter(
              description = "Immutable course-generation run identifier",
              schema = @Schema(format = "uuid", minLength = 36, maxLength = 36))
          @PathVariable
          UUID runId,
      HttpServletRequest request,
      HttpServletResponse response) {
    HttpHeaders requestHeaders = new HttpHeaders();
    ProxyHeaderUtils.copyRequestHeaders(request, requestHeaders);

    response.setContentType(MediaType.TEXT_EVENT_STREAM_VALUE);
    response.setHeader(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL);
    response.setHeader("X-Accel-Buffering", "no");

    String targetUri =
        mcpProxyService.resolvePluginBaseUrl(PLUGIN_SLUG)
            + request.getRequestURI()
            + querySuffix(request);
    return outputStream -> proxy.stream(requestHeaders, response, outputStream, targetUri);
  }

  private static String querySuffix(HttpServletRequest request) {
    return request.getQueryString() == null ? "" : "?" + request.getQueryString();
  }
}
