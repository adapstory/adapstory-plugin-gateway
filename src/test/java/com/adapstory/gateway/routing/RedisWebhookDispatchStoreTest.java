package com.adapstory.gateway.routing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import tools.jackson.databind.ObjectMapper;

class RedisWebhookDispatchStoreTest {
  private static final String KEY = "550e8400-e29b-41d4-a716-446655440000";
  private static final String REDIS_KEY = "gateway:webhook:v1:job:" + KEY;

  @Test
  @SuppressWarnings("unchecked")
  void atomicAdmissionBindsOneKeyToOnePayload() {
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    ValueOperations<String, String> values = mock(ValueOperations.class);
    when(redis.opsForValue()).thenReturn(values);
    RedisWebhookDispatchStore store = new RedisWebhookDispatchStore(redis, new ObjectMapper());
    WebhookDispatchJob original = job("first");
    ArgumentCaptor<String> stored = ArgumentCaptor.forClass(String.class);
    when(values.setIfAbsent(eq(REDIS_KEY), stored.capture())).thenReturn(true, false, false);

    assertThat(store.admit(original)).isEqualTo(WebhookDispatchStore.Admission.NEW);
    when(values.get(REDIS_KEY)).thenReturn(stored.getValue());
    assertThat(store.admit(job("first"))).isEqualTo(WebhookDispatchStore.Admission.REPLAY);
    assertThat(store.admit(job("different"))).isEqualTo(WebhookDispatchStore.Admission.CONFLICT);
  }

  @Test
  @SuppressWarnings("unchecked")
  void storageFailureDoesNotBecomeAnAdmission() {
    StringRedisTemplate redis = mock(StringRedisTemplate.class);
    ValueOperations<String, String> values = mock(ValueOperations.class);
    when(redis.opsForValue()).thenReturn(values);
    when(values.setIfAbsent(eq(REDIS_KEY), org.mockito.ArgumentMatchers.anyString()))
        .thenThrow(new IllegalStateException("redis down"));

    RedisWebhookDispatchStore store = new RedisWebhookDispatchStore(redis, new ObjectMapper());
    assertThatThrownBy(() -> store.admit(job("first")))
        .isInstanceOf(WebhookDispatchStorageException.class)
        .hasMessageNotContaining(KEY);
  }

  private static WebhookDispatchJob job(String payload) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.set("X-Idempotency-Key", KEY);
    return WebhookDispatchJob.from(
        KEY, "plugin", "http://plugin:8080/webhook", payload.getBytes(), headers);
  }
}
