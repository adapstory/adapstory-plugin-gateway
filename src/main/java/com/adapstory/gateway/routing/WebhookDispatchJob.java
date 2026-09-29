package com.adapstory.gateway.routing;

import com.adapstory.commons.header.IntegrationHeaders;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/** A persisted webhook delivery request. Payloads must follow the webhook data contract. */
record WebhookDispatchJob(
    String idempotencyKey,
    String pluginShortId,
    String pluginPodUrl,
    String payloadBase64,
    String contentType,
    String correlationId,
    String fingerprint,
    State state) {

  enum State {
    PENDING,
    DELIVERED,
    REJECTED
  }

  static WebhookDispatchJob from(
      String idempotencyKey,
      String pluginShortId,
      String pluginPodUrl,
      byte[] payload,
      HttpHeaders headers) {
    String contentType =
        headers.getContentType() == null
            ? MediaType.APPLICATION_JSON_VALUE
            : headers.getContentType().toString();
    return new WebhookDispatchJob(
        idempotencyKey,
        pluginShortId,
        pluginPodUrl,
        Base64.getEncoder().encodeToString(payload),
        contentType,
        headers.getFirst(IntegrationHeaders.HEADER_CORRELATION_ID),
        fingerprint(pluginShortId, contentType, payload),
        State.PENDING);
  }

  byte[] payload() {
    return Base64.getDecoder().decode(payloadBase64);
  }

  HttpHeaders deliveryHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.parseMediaType(contentType));
    headers.set("X-Idempotency-Key", idempotencyKey);
    if (correlationId != null) {
      headers.set(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);
    }
    return headers;
  }

  WebhookDispatchJob withState(State newState) {
    return new WebhookDispatchJob(
        idempotencyKey,
        pluginShortId,
        pluginPodUrl,
        newState == State.PENDING ? payloadBase64 : "",
        contentType,
        correlationId,
        fingerprint,
        newState);
  }

  private static String fingerprint(String pluginShortId, String contentType, byte[] payload) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(pluginShortId.getBytes(StandardCharsets.UTF_8));
      digest.update((byte) 0);
      digest.update(contentType.getBytes(StandardCharsets.UTF_8));
      digest.update((byte) 0);
      digest.update(payload);
      return HexFormat.of().formatHex(digest.digest());
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
