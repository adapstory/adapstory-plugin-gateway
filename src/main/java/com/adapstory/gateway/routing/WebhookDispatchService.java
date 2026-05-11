package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.config.GatewayProperties;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import java.net.URI;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Service for dispatching webhooks to plugin pods with retry and async execution.
 *
 * <p>Extracted from {@code WebhookDispatcher} (GRASP C-2, HC-2) to isolate dispatch mechanics
 * (retry, async execution, endpoint resolution, HTTP delivery) from the REST controller concern.
 *
 * <p>Responsibilities:
 *
 * <ul>
 *   <li>Create RestClient with connect/read timeout (PV-2)
 *   <li>Configure Resilience4j Retry with exponential backoff
 *   <li>Resolve plugin pod endpoint from K8s naming convention
 *   <li>Async dispatch with CompletableFuture
 * </ul>
 */
@Service
public class WebhookDispatchService {

  private static final Logger log = LoggerFactory.getLogger(WebhookDispatchService.class);

  private static final int CONNECT_TIMEOUT_MS = 3000;
  private static final int READ_TIMEOUT_MS = 3000;

  private final GatewayProperties properties;
  private final RestClient restClient;
  private final Executor webhookExecutor;
  private final Retry webhookRetry;

  public WebhookDispatchService(
      GatewayProperties properties,
      RestClient.Builder restClientBuilder,
      @Qualifier("webhookExecutor") Executor webhookExecutor) {
    this.properties = properties;
    this.webhookExecutor = webhookExecutor;

    var factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(java.time.Duration.ofMillis(CONNECT_TIMEOUT_MS));
    factory.setReadTimeout(java.time.Duration.ofMillis(READ_TIMEOUT_MS));
    this.restClient = restClientBuilder.requestFactory(factory).build();

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
