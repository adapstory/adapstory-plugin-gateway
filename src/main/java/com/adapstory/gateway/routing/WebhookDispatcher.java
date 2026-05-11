package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import com.adapstory.gateway.util.PluginSlugValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.annotation.security.PermitAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for incoming webhooks from Core BC.
 *
 * <p>Handles POST /api/bc-02/gateway/v1/webhooks/{pluginShortId}, validates the request, and
 * delegates async dispatch to {@link WebhookDispatchService}.
 *
 * <p>Responsibilities (single: HTTP endpoint + request validation):
 *
 * <ul>
 *   <li>Accept HTTP POST request
 *   <li>Validate pluginShortId format
 *   <li>Verify internal secret
 *   <li>Delegate to WebhookDispatchService
 * </ul>
 */
@PermitAll
@RestController
@RequestMapping("/api/bc-02/gateway/v1/webhooks")
public class WebhookDispatcher {

  private static final Logger log = LoggerFactory.getLogger(WebhookDispatcher.class);

  private final GatewayProperties properties;
  private final WebhookDispatchService dispatchService;

  public WebhookDispatcher(GatewayProperties properties, WebhookDispatchService dispatchService) {
    this.properties = properties;
    this.dispatchService = dispatchService;
  }

  @Operation(
      summary = "Dispatch webhook to plugin pod",
      description =
          "Forwards CloudEvents 1.0 payload from core BC to the target plugin pod. "
              + "Dispatch is async (returns 202 immediately). Retries with exponential backoff.")
  @ApiResponse(responseCode = "202", description = "Webhook accepted for async delivery")
  @ApiResponse(responseCode = "400", description = "Invalid plugin short ID")
  @ApiResponse(responseCode = "403", description = "Invalid internal secret")
  @PostMapping("/{pluginShortId}")
  public ResponseEntity<Void> dispatchWebhook(
      @Parameter(description = "Plugin short identifier") @PathVariable String pluginShortId,
      @RequestBody byte[] payload,
      @RequestHeader HttpHeaders headers) {
    if (!PluginSlugValidator.isValidSlug(pluginShortId)) {
      log.warn("Webhook dispatch rejected: invalid pluginShortId '{}'", pluginShortId);
      return ResponseEntity.badRequest().build();
    }

    String configuredSecret = properties.webhook().internalSecret();
    if (configuredSecret != null && !configuredSecret.isBlank()) {
      String providedSecret = headers.getFirst(IntegrationHeaders.HEADER_INTERNAL_SECRET);
      if (!java.security.MessageDigest.isEqual(
          configuredSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8),
          (providedSecret != null ? providedSecret : "")
              .getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
        log.warn(
            "Webhook dispatch rejected: invalid or missing internal secret for plugin '{}'",
            pluginShortId);
        return ResponseEntity.status(403).build();
      }
    }

    String pluginPodUrl = dispatchService.resolvePluginPodEndpoint(pluginShortId);
    dispatchService.dispatchAsync(pluginShortId, pluginPodUrl, payload, headers);

    return ResponseEntity.accepted().build();
  }

  /**
   * Resolve plugin pod endpoint — delegates to {@link WebhookDispatchService}.
   *
   * <p>Kept for binary compatibility with existing tests.
   */
  String resolvePluginPodEndpoint(String pluginShortId) {
    return dispatchService.resolvePluginPodEndpoint(pluginShortId);
  }
}
