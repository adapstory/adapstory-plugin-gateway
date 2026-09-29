package com.adapstory.gateway.routing;

import java.util.List;
import java.util.Optional;

interface WebhookDispatchStore {
  enum Admission {
    NEW,
    REPLAY,
    CONFLICT
  }

  Admission admit(WebhookDispatchJob job);

  Optional<WebhookDispatchJob> load(String idempotencyKey);

  List<String> pendingKeys();

  Optional<String> claim(String idempotencyKey);

  void complete(WebhookDispatchJob job, String claim);

  void release(String idempotencyKey, String claim);
}
