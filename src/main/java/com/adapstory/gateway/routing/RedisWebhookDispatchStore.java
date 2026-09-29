package com.adapstory.gateway.routing;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/** Shared durable admission and recovery state for webhook delivery. */
@Component
final class RedisWebhookDispatchStore implements WebhookDispatchStore {
  private static final String PREFIX = "gateway:webhook:v1:";
  private static final Duration CLAIM_TTL = Duration.ofMinutes(2);
  private static final DefaultRedisScript<Long> COMPLETE_SCRIPT =
      script(
          "if redis.call('GET',KEYS[1]) == ARGV[1] then "
              + "redis.call('SET',KEYS[2],ARGV[2]); "
              + "redis.call('DEL',KEYS[1]); return 1 end; return 0");
  private static final DefaultRedisScript<Long> RELEASE_SCRIPT =
      script(
          "if redis.call('GET',KEYS[1]) == ARGV[1] then "
              + "return redis.call('DEL',KEYS[1]) end; return 0");

  private final StringRedisTemplate redis;
  private final ObjectMapper mapper;

  RedisWebhookDispatchStore(StringRedisTemplate redis, ObjectMapper mapper) {
    this.redis = redis;
    this.mapper = mapper;
  }

  @Override
  public Admission admit(WebhookDispatchJob job) {
    try {
      String key = jobKey(job.idempotencyKey());
      if (Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, encode(job)))) {
        return Admission.NEW;
      }
      WebhookDispatchJob previous =
          load(job.idempotencyKey())
              .orElseThrow(() -> new IllegalStateException("webhook admission disappeared"));
      return previous.fingerprint().equals(job.fingerprint())
          ? Admission.REPLAY
          : Admission.CONFLICT;
    } catch (RuntimeException exception) {
      throw storageFailure(exception);
    }
  }

  @Override
  public Optional<WebhookDispatchJob> load(String idempotencyKey) {
    try {
      String value = redis.opsForValue().get(jobKey(idempotencyKey));
      return value == null ? Optional.empty() : Optional.of(decode(value));
    } catch (RuntimeException exception) {
      throw storageFailure(exception);
    }
  }

  @Override
  public List<String> pendingKeys() {
    try {
      List<String> pending = new ArrayList<>();
      ScanOptions options = ScanOptions.scanOptions().match(PREFIX + "job:*").count(100).build();
      try (Cursor<String> cursor = redis.scan(options)) {
        while (cursor.hasNext()) {
          String key = cursor.next();
          String value = redis.opsForValue().get(key);
          if (value != null && decode(value).state() == WebhookDispatchJob.State.PENDING) {
            pending.add(key.substring((PREFIX + "job:").length()));
          }
        }
      }
      return pending;
    } catch (RuntimeException exception) {
      throw storageFailure(exception);
    }
  }

  @Override
  public Optional<String> claim(String idempotencyKey) {
    try {
      String token = UUID.randomUUID().toString();
      return Boolean.TRUE.equals(
              redis.opsForValue().setIfAbsent(leaseKey(idempotencyKey), token, CLAIM_TTL))
          ? Optional.of(token)
          : Optional.empty();
    } catch (RuntimeException exception) {
      throw storageFailure(exception);
    }
  }

  @Override
  public void complete(WebhookDispatchJob job, String claim) {
    try {
      Long completed =
          redis.execute(
              COMPLETE_SCRIPT,
              List.of(leaseKey(job.idempotencyKey()), jobKey(job.idempotencyKey())),
              claim,
              encode(job));
      if (!Long.valueOf(1).equals(completed)) {
        throw new IllegalStateException("webhook delivery claim expired");
      }
    } catch (RuntimeException exception) {
      throw storageFailure(exception);
    }
  }

  @Override
  public void release(String idempotencyKey, String claim) {
    try {
      redis.execute(RELEASE_SCRIPT, List.of(leaseKey(idempotencyKey)), claim);
    } catch (RuntimeException exception) {
      throw storageFailure(exception);
    }
  }

  private String encode(WebhookDispatchJob job) {
    try {
      return mapper.writeValueAsString(job);
    } catch (tools.jackson.core.JacksonException exception) {
      throw new IllegalStateException("webhook dispatch state is invalid", exception);
    }
  }

  private WebhookDispatchJob decode(String value) {
    try {
      return mapper.readValue(value, WebhookDispatchJob.class);
    } catch (tools.jackson.core.JacksonException exception) {
      throw new IllegalStateException("webhook dispatch state is corrupt", exception);
    }
  }

  private static String jobKey(String idempotencyKey) {
    return PREFIX + "job:" + idempotencyKey;
  }

  private static String leaseKey(String idempotencyKey) {
    return PREFIX + "lease:" + idempotencyKey;
  }

  private static DefaultRedisScript<Long> script(String source) {
    DefaultRedisScript<Long> script = new DefaultRedisScript<>();
    script.setScriptText(source);
    script.setResultType(Long.class);
    return script;
  }

  private static WebhookDispatchStorageException storageFailure(RuntimeException cause) {
    return new WebhookDispatchStorageException("webhook dispatch storage unavailable", cause);
  }
}
