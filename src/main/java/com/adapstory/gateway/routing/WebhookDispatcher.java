package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Диспетчер webhook-ов: Core BC → Plugin Pod.
 *
 * <p>Принимает POST /api/bc-02/gateway/v1/webhooks/{pluginShortId} от core BC, разрешает endpoint
 * plugin pod из registry и форвардит CloudEvents 1.0 payload. Dispatch выполняется асинхронно,
 * endpoint немедленно возвращает 202 Accepted. Retry с экспоненциальным backoff (3 попытки: 1s, 2s,
 * 4s), только для 5xx и connection errors (4xx не ретраится).
 */
@RestController
@RequestMapping("/api/bc-02/gateway/v1/webhooks")
public class WebhookDispatcher {

  private static final Logger log = LoggerFactory.getLogger(WebhookDispatcher.class);

  private final GatewayProperties properties;
  private final RestClient restClient;
  private final Executor webhookExecutor;

  public WebhookDispatcher(
      GatewayProperties properties,
      RestClient.Builder restClientBuilder,
      @Qualifier("webhookExecutor") Executor webhookExecutor) {
    this.properties = properties;
    this.restClient = restClientBuilder.build();
    this.webhookExecutor = webhookExecutor;
  }

  private static final String INTERNAL_SECRET_HEADER = "X-Internal-Secret";
  private static final Pattern PLUGIN_SHORT_ID_PATTERN =
      Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]*$");

  @PostMapping("/{pluginShortId}")
  public ResponseEntity<Void> dispatchWebhook(
      @PathVariable String pluginShortId,
      @RequestBody byte[] payload,
      @RequestHeader HttpHeaders headers) {
    if (!PLUGIN_SHORT_ID_PATTERN.matcher(pluginShortId).matches()) {
      log.warn("Webhook dispatch rejected: invalid pluginShortId '{}'", pluginShortId);
      return ResponseEntity.badRequest().build();
    }

    String configuredSecret = properties.webhook().internalSecret();
    if (configuredSecret != null && !configuredSecret.isBlank()) {
      String providedSecret = headers.getFirst(INTERNAL_SECRET_HEADER);
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

    String pluginPodUrl = resolvePluginPodEndpoint(pluginShortId);
    log.info("Dispatching webhook to plugin '{}' at {}", pluginShortId, pluginPodUrl);

    CompletableFuture.runAsync(
            () -> executeWithRetry(pluginShortId, pluginPodUrl, payload, headers), webhookExecutor)
        .exceptionally(
            ex -> {
              log.error(
                  "Unhandled error dispatching webhook to plugin '{}': {}",
                  pluginShortId,
                  ex.getMessage());
              return null;
            });

    return ResponseEntity.accepted().build();
  }

  /**
   * Execute webhook dispatch with retry logic. Package-private for testability.
   *
   * <p>Retries only on 5xx / connection errors. 4xx client errors are NOT retried.
   */
  void executeWithRetry(
      String pluginShortId, String pluginPodUrl, byte[] payload, HttpHeaders headers) {
    GatewayProperties.WebhookConfig webhookConfig = properties.webhook();
    int maxAttempts = webhookConfig.retryMaxAttempts();
    long intervalMs = webhookConfig.retryInitialIntervalMs();
    double multiplier = webhookConfig.retryMultiplier();

    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        restClient
            .post()
            .uri(URI.create(pluginPodUrl))
            .headers(
                h -> {
                  if (headers.getContentType() != null) {
                    h.setContentType(headers.getContentType());
                  } else {
                    h.setContentType(MediaType.APPLICATION_JSON);
                  }
                  String correlationId = headers.getFirst(IntegrationHeaders.HEADER_CORRELATION_ID);
                  if (correlationId != null) {
                    h.set(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);
                  }
                })
            .body(payload)
            .retrieve()
            .toBodilessEntity();

        log.info(
            "Webhook dispatched successfully to plugin '{}' on attempt {}", pluginShortId, attempt);
        return;
      } catch (HttpClientErrorException ex) {
        // 4xx — client error, do NOT retry
        log.warn(
            "Webhook dispatch to plugin '{}' got client error (not retrying): {} {}",
            pluginShortId,
            ex.getStatusCode(),
            ex.getMessage());
        return;
      } catch (Exception ex) {
        log.warn(
            "Webhook dispatch to plugin '{}' failed on attempt {}/{}: {}",
            pluginShortId,
            attempt,
            maxAttempts,
            ex.getMessage());

        if (attempt < maxAttempts) {
          try {
            Thread.sleep(intervalMs);
          } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            log.warn("Webhook dispatch interrupted for plugin '{}'", pluginShortId);
            return;
          }
          intervalMs = (long) (intervalMs * multiplier);
        }
      }
    }

    log.error(
        "Webhook dispatch to plugin '{}' failed after {} attempts", pluginShortId, maxAttempts);
  }

  /**
   * Resolve plugin pod endpoint from K8s service name convention. Format:
   * http://plugin-{pluginShortId}:{port}/webhook
   */
  String resolvePluginPodEndpoint(String pluginShortId) {
    GatewayProperties.WebhookConfig cfg = properties.webhook();
    String host = String.format(cfg.pluginPodHostTemplate(), pluginShortId);
    return String.format("http://%s:%d/webhook", host, cfg.pluginPodPort());
  }
}
