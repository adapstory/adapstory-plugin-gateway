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
import org.springframework.scheduling.annotation.Scheduled;
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

  enum DispatchOutcome {
    DELIVERED,
    REJECTED,
    RETRY_LATER
  }

  private static final Logger log = LoggerFactory.getLogger(WebhookDispatchService.class);

  private final GatewayProperties properties;
  private final WebhookDeliveryPort deliveryPort;
  private final Executor webhookExecutor;
  private final Retry webhookRetry;
  private final WebhookDispatchStore store;

  public WebhookDispatchService(
      GatewayProperties properties,
      WebhookDeliveryPort deliveryPort,
      @Qualifier("webhookExecutor") Executor webhookExecutor,
      WebhookDispatchStore store) {
    this.properties = properties;
    this.deliveryPort = deliveryPort;
    this.webhookExecutor = webhookExecutor;
    this.store = store;

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

  /** Stores the exact command before an asynchronous delivery can be acknowledged. */
  public WebhookDispatchStore.Admission accept(
      String idempotencyKey,
      String pluginShortId,
      String pluginPodUrl,
      byte[] payload,
      HttpHeaders headers) {
    WebhookDispatchJob job =
        WebhookDispatchJob.from(idempotencyKey, pluginShortId, pluginPodUrl, payload, headers);
    WebhookDispatchStore.Admission admission = store.admit(job);
    if (admission == WebhookDispatchStore.Admission.NEW) {
      schedule(idempotencyKey);
    }
    return admission;
  }

  /** Resumes persisted work after a process restart or an executor rejection. */
  @Scheduled(fixedDelayString = "${gateway.webhook.recovery-interval-ms:5000}")
  void recoverPending() {
    try {
      for (String key : store.pendingKeys()) {
        schedule(key);
      }
    } catch (WebhookDispatchStorageException exception) {
      log.error("Webhook recovery storage is unavailable", exception);
    }
  }

  private void schedule(String idempotencyKey) {
    try {
      CompletableFuture.runAsync(() -> dispatchPersisted(idempotencyKey), webhookExecutor)
          .exceptionally(
              ex -> {
                log.error("Unhandled error dispatching persisted webhook", ex);
                return null;
              });
    } catch (RuntimeException exception) {
      log.error("Webhook executor rejected persisted delivery; recovery will retry", exception);
    }
  }

  private void dispatchPersisted(String idempotencyKey) {
    var claim = store.claim(idempotencyKey);
    if (claim.isEmpty()) {
      return;
    }
    boolean completed = false;
    try {
      var job = store.load(idempotencyKey);
      if (job.isPresent() && job.get().state() == WebhookDispatchJob.State.PENDING) {
        WebhookDispatchJob pending = job.get();
        DispatchOutcome outcome =
            executeWithRetry(
                pending.pluginShortId(),
                pending.pluginPodUrl(),
                pending.payload(),
                pending.deliveryHeaders());
        if (outcome != DispatchOutcome.RETRY_LATER) {
          store.complete(
              pending.withState(
                  outcome == DispatchOutcome.DELIVERED
                      ? WebhookDispatchJob.State.DELIVERED
                      : WebhookDispatchJob.State.REJECTED),
              claim.get());
          completed = true;
        }
      }
    } finally {
      if (!completed) {
        store.release(idempotencyKey, claim.get());
      }
    }
  }

  /**
   * Execute webhook dispatch with Resilience4j Retry. Package-private for testability.
   *
   * <p>Retries only on 5xx / connection errors. 4xx client errors are ignored by Retry (not
   * retried) and caught here.
   */
  DispatchOutcome executeWithRetry(
      String pluginShortId, String pluginPodUrl, byte[] payload, HttpHeaders headers) {
    try {
      webhookRetry.executeRunnable(() -> sendWebhook(pluginPodUrl, payload, headers));
      log.info("Webhook dispatched successfully to plugin '{}'", pluginShortId);
      return DispatchOutcome.DELIVERED;
    } catch (HttpClientErrorException ex) {
      log.warn(
          "Webhook dispatch to plugin '{}' got client error (not retrying): {} {}",
          pluginShortId,
          ex.getStatusCode(),
          ex.getMessage());
      return DispatchOutcome.REJECTED;
    } catch (Exception ex) {
      log.error(
          "Webhook dispatch to plugin '{}' failed after {} attempts: {}",
          pluginShortId,
          properties.webhook().retryMaxAttempts(),
          ex.getMessage());
      return DispatchOutcome.RETRY_LATER;
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
