package com.adapstory.gateway.routing;

import com.adapstory.gateway.config.GatewayProperties;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

/**
 * Service for dispatching webhooks to plugin pods with retry and async execution.
 *
 * <p>Extracted from {@code WebhookDispatcher} (GRASP C-2, HC-2) to isolate dispatch mechanics
 * (retry, async execution, endpoint resolution, HTTP delivery) from the REST controller concern.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Delegate HTTP delivery to dedicated transport adapter (PV-2)
 *   <li>Configure Resilience4j Retry with exponential backoff
 *   <li>Resolve plugin pod endpoint from K8s naming convention
 *   <li>Async dispatch with CompletableFuture
 * </ul>
 */
@Service
public class WebhookDispatchService {

  private static final Logger log = LoggerFactory.getLogger(WebhookDispatchService.class);

  private final GatewayProperties properties;
  private final WebhookDeliveryPort deliveryPort;
  private final Executor webhookExecutor;
  private final Retry webhookRetry;

  public WebhookDispatchService(
      GatewayProperties properties,
      WebhookDeliveryPort deliveryPort,
      @Qualifier("webhookExecutor") Executor webhookExecutor) {
    this.properties = properties;
    this.deliveryPort = deliveryPort;
    this.webhookExecutor = webhookExecutor;

    GatewayProperties.WebhookConfig cfg = properties.webhook();
    RetryConfig retryConfig =
        RetryConfig.custom()
            .maxAttempts(cfg.retryMaxAttempts())
            .intervalFunction(
                io.github.resilience4j.core.IntervalFunction.ofExponentialBackoff(
                    cfg.retryInitialIntervalMs(), cfg.retryMultiplier()))
            .ignoreExceptions(HttpClientErrorException.class)
            .build();
    this.webhookRetry = RetryRegistry.of(retryConfig).retry("webhook-dispatch");
  }

  /**
   * Dispatches a webhook asynchronously to the plugin pod endpoint.
   *
   * @param pluginShortId plugin short identifier for logging
   * @param pluginPodUrl resolved target URL
   * @param payload raw request body
   * @param headers original request headers
   */
  public void dispatchAsync(
      String pluginShortId, String pluginPodUrl, byte[] payload, HttpHeaders headers) {
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
  }

  /**
   * Execute webhook dispatch with Resilience4j Retry. Package-private for testability.
   *
   * <p>Retries only on 5xx / connection errors. 4xx client errors are ignored by Retry (not
   * retried) and caught here.
   */
  void executeWithRetry(
      String pluginShortId, String pluginPodUrl, byte[] payload, HttpHeaders headers) {
    try {
      webhookRetry.executeRunnable(() -> sendWebhook(pluginPodUrl, payload, headers));
      log.info("Webhook dispatched successfully to plugin '{}'", pluginShortId);
    } catch (HttpClientErrorException ex) {
      log.warn(
          "Webhook dispatch to plugin '{}' got client error (not retrying): {} {}",
          pluginShortId,
          ex.getStatusCode(),
          ex.getMessage());
    } catch (Exception ex) {
      log.error(
          "Webhook dispatch to plugin '{}' failed after {} attempts: {}",
          pluginShortId,
          properties.webhook().retryMaxAttempts(),
          ex.getMessage());
    }
  }

  private void sendWebhook(String pluginPodUrl, byte[] payload, HttpHeaders headers) {
    deliveryPort.send(pluginPodUrl, payload, headers);
  }

  /**
   * Resolve plugin pod endpoint from K8s service name convention. Format:
   * http://plugin-{pluginShortId}:{port}/webhook
   */
  public String resolvePluginPodEndpoint(String pluginShortId) {
    GatewayProperties.WebhookConfig cfg = properties.webhook();
    String host = String.format(cfg.pluginPodHostTemplate(), pluginShortId);
    return String.format("http://%s:%d/webhook", host, cfg.pluginPodPort());
  }
}
