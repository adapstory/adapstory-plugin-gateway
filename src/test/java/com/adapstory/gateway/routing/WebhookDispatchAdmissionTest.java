package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.adapstory.gateway.config.GatewayProperties;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;

class WebhookDispatchAdmissionTest {
  private static final String KEY = "550e8400-e29b-41d4-a716-446655440000";

  @Test
  void persistsBeforeAcknowledgementAndCoalescesIdenticalReplay() {
    MemoryStore store = new MemoryStore();
    Queue<Runnable> queued = new ArrayDeque<>();
    WebhookDeliveryPort delivery = mock(WebhookDeliveryPort.class);
    WebhookDispatcher controller = controller(store, queued::add, delivery);
    HttpHeaders headers = headers();

    assertThat(
            controller
                .dispatchWebhook("sample", "one".getBytes(), KEY, headers)
                .getStatusCode()
                .value())
        .isEqualTo(202);
    assertThat(store.load(KEY)).isPresent();
    verifyNoInteractions(delivery);
    assertThat(
            controller
                .dispatchWebhook("sample", "one".getBytes(), KEY, headers)
                .getStatusCode()
                .value())
        .isEqualTo(202);
    assertThat(queued).hasSize(1);
    assertThat(
            controller
                .dispatchWebhook("sample", "two".getBytes(), KEY, headers)
                .getStatusCode()
                .value())
        .isEqualTo(409);

    queued.remove().run();
    verify(delivery).send(any(), any(), any());
    assertThat(store.load(KEY).orElseThrow().state()).isEqualTo(WebhookDispatchJob.State.DELIVERED);
    assertThat(store.load(KEY).orElseThrow().payloadBase64()).isEmpty();
    assertThat(
            controller
                .dispatchWebhook("sample", "one".getBytes(), KEY, headers)
                .getStatusCode()
                .value())
        .isEqualTo(202);
    assertThat(queued).isEmpty();
  }

  @Test
  void unavailableStorageCannotAcknowledgeWebhook() {
    MemoryStore store = new MemoryStore();
    store.unavailable = true;
    Queue<Runnable> queued = new ArrayDeque<>();
    WebhookDeliveryPort delivery = mock(WebhookDeliveryPort.class);

    assertThat(
            controller(store, queued::add, delivery)
                .dispatchWebhook("sample", "one".getBytes(), KEY, headers())
                .getStatusCode()
                .value())
        .isEqualTo(503);
    assertThat(queued).isEmpty();
    verifyNoInteractions(delivery);
  }

  @Test
  void aNewProcessRecoversPersistedPendingDelivery() {
    MemoryStore store = new MemoryStore();
    Queue<Runnable> oldQueue = new ArrayDeque<>();
    WebhookDeliveryPort delivery = mock(WebhookDeliveryPort.class);
    WebhookDispatcher oldController = controller(store, oldQueue::add, delivery);
    assertThat(
            oldController
                .dispatchWebhook("sample", "one".getBytes(), KEY, headers())
                .getStatusCode()
                .value())
        .isEqualTo(202);

    Queue<Runnable> newQueue = new ArrayDeque<>();
    WebhookDispatchService newProcess = service(store, newQueue::add, delivery);
    newProcess.recoverPending();
    assertThat(newQueue).hasSize(1);
    newQueue.remove().run();
    assertThat(store.load(KEY).orElseThrow().state()).isEqualTo(WebhookDispatchJob.State.DELIVERED);
    newProcess.recoverPending();
    assertThat(newQueue).isEmpty();
    verify(delivery).send(any(), any(), any());
  }

  @Test
  void permanentClientRejectionClosesTheCommandWithoutRepeatingIt() {
    MemoryStore store = new MemoryStore();
    WebhookDeliveryPort delivery = mock(WebhookDeliveryPort.class);
    doThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST))
        .when(delivery)
        .send(any(), any(), any());
    WebhookDispatcher controller = controller(store, Runnable::run, delivery);

    assertThat(
            controller
                .dispatchWebhook("sample", "one".getBytes(), KEY, headers())
                .getStatusCode()
                .value())
        .isEqualTo(202);
    assertThat(store.load(KEY).orElseThrow().state()).isEqualTo(WebhookDispatchJob.State.REJECTED);
    assertThat(store.pendingKeys()).isEmpty();
    assertThat(
            controller
                .dispatchWebhook("sample", "one".getBytes(), KEY, headers())
                .getStatusCode()
                .value())
        .isEqualTo(202);
    verify(delivery).send(any(), any(), any());
  }

  private static WebhookDispatcher controller(
      WebhookDispatchStore store, Executor executor, WebhookDeliveryPort delivery) {
    GatewayProperties properties = properties();
    return new WebhookDispatcher(
        properties, new WebhookDispatchService(properties, delivery, executor, store));
  }

  private static WebhookDispatchService service(
      WebhookDispatchStore store, Executor executor, WebhookDeliveryPort delivery) {
    return new WebhookDispatchService(properties(), delivery, executor, store);
  }

  private static HttpHeaders headers() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set("X-Idempotency-Key", KEY);
    return headers;
  }

  private static GatewayProperties properties() {
    return new GatewayProperties(
        new GatewayProperties.JwtConfig("http://localhost/certs", "issuer", "audience", 5),
        Map.of(),
        Map.of(),
        new GatewayProperties.PermissionsConfig(Map.of()),
        new GatewayProperties.PermissionCacheConfig(5, "plugin:permissions:"),
        new GatewayProperties.InstalledCacheConfig(5, 30),
        new GatewayProperties.WebhookConfig(1, 1, 2.0, 8080, null, null),
        new GatewayProperties.Bc02Config("http://localhost:8081"),
        null);
  }

  private static final class MemoryStore implements WebhookDispatchStore {
    private final Map<String, WebhookDispatchJob> jobs = new HashMap<>();
    private final Map<String, String> claims = new HashMap<>();
    private boolean unavailable;

    @Override
    public synchronized Admission admit(WebhookDispatchJob job) {
      if (unavailable) {
        throw new WebhookDispatchStorageException(
            "storage unavailable", new IllegalStateException());
      }
      WebhookDispatchJob previous = jobs.putIfAbsent(job.idempotencyKey(), job);
      if (previous == null) {
        return Admission.NEW;
      }
      return previous.fingerprint().equals(job.fingerprint())
          ? Admission.REPLAY
          : Admission.CONFLICT;
    }

    @Override
    public synchronized Optional<WebhookDispatchJob> load(String idempotencyKey) {
      return Optional.ofNullable(jobs.get(idempotencyKey));
    }

    @Override
    public synchronized List<String> pendingKeys() {
      List<String> pending = new ArrayList<>();
      jobs.forEach(
          (key, job) -> {
            if (job.state() == WebhookDispatchJob.State.PENDING) {
              pending.add(key);
            }
          });
      return pending;
    }

    @Override
    public synchronized Optional<String> claim(String idempotencyKey) {
      return claims.putIfAbsent(idempotencyKey, "claim") == null
          ? Optional.of("claim")
          : Optional.empty();
    }

    @Override
    public synchronized void complete(WebhookDispatchJob job, String claim) {
      if (!claim.equals(claims.remove(job.idempotencyKey()))) {
        throw new IllegalStateException("lost claim");
      }
      jobs.put(job.idempotencyKey(), job);
    }

    @Override
    public synchronized void release(String idempotencyKey, String claim) {
      claims.remove(idempotencyKey, claim);
    }
  }
}
