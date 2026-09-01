package com.adapstory.gateway.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class CredentialTaskCapabilityTest {

  @Test
  void acceptsOnlyCanonicalExactCapabilityNames() {
    assertThat(CredentialCapability.requireExact("credential.lifecycle.contain"))
        .isEqualTo(CredentialCapability.CONTAIN);
    assertThatThrownBy(() -> CredentialCapability.requireExact("credential.lifecycle.apply.extra"))
        .isInstanceOf(CredentialCapabilityRejectedException.class);
  }

  @Test
  void rejectsCrossTaskAndCrossAgentReuse() {
    Instant now = Instant.parse("2026-09-01T12:00:00Z");
    CredentialTaskCapability capability =
        new CredentialTaskCapability(
            "CredentialTaskCapability/v1",
            "cap-1",
            CredentialCapability.APPLY,
            "adapstory-i6u28",
            "codex-thread:one",
            "policy-digest",
            now,
            now.plusSeconds(60));

    capability.requireCaller(
        "adapstory-i6u28", "codex-thread:one", CredentialCapability.APPLY, now);
    assertThatThrownBy(
            () ->
                capability.requireCaller(
                    "adapstory-other", "codex-thread:one", CredentialCapability.APPLY, now))
        .isInstanceOf(CredentialCapabilityRejectedException.class);
    assertThatThrownBy(
            () ->
                capability.requireCaller(
                    "adapstory-i6u28", "codex-thread:two", CredentialCapability.APPLY, now))
        .isInstanceOf(CredentialCapabilityRejectedException.class);
  }

  @Test
  void containmentCannotBecomeGenericApply() {
    Instant now = Instant.parse("2026-09-01T12:00:00Z");
    CredentialTaskCapability capability =
        new CredentialTaskCapability(
            "CredentialTaskCapability/v1",
            "cap-2",
            CredentialCapability.CONTAIN,
            "adapstory-i6u28",
            "codex-thread:one",
            "policy-digest",
            now,
            now.plusSeconds(60));
    assertThatThrownBy(
            () ->
                capability.requireCaller(
                    "adapstory-i6u28", "codex-thread:one", CredentialCapability.APPLY, now))
        .isInstanceOf(CredentialCapabilityRejectedException.class);
  }
}
