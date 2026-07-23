package com.adapstory.gateway.mcpgrant;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Registers and loads short-lived exact provider grants without an in-process authorization copy.
 */
@Service
public final class McpGrantService {

  private final McpGrantStore store;
  private final ProviderBindingVerifier verifier;
  private final Clock clock;
  private final Duration maximumTtl;
  private final Duration minimumValidity;
  private final Duration replayRetention;

  @Autowired
  public McpGrantService(
      McpGrantStore store,
      ProviderBindingVerifier verifier,
      @Value("${gateway.mcp.grants.maximum-ttl-seconds:300}") long maximumTtlSeconds,
      @Value("${gateway.mcp.grants.minimum-validity-seconds:5}") long minimumValiditySeconds,
      @Value("${gateway.mcp.grants.replay-retention-seconds:60}") long replayRetentionSeconds) {
    this(
        store,
        verifier,
        Clock.systemUTC(),
        Duration.ofSeconds(maximumTtlSeconds),
        Duration.ofSeconds(minimumValiditySeconds),
        Duration.ofSeconds(replayRetentionSeconds));
  }

  McpGrantService(
      McpGrantStore store,
      ProviderBindingVerifier verifier,
      Clock clock,
      Duration maximumTtl,
      Duration minimumValidity,
      Duration replayRetention) {
    this.store = Objects.requireNonNull(store, "store must not be null");
    this.verifier = Objects.requireNonNull(verifier, "verifier must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.maximumTtl = requirePositive(maximumTtl, "maximumTtl");
    this.minimumValidity = requirePositive(minimumValidity, "minimumValidity");
    this.replayRetention = requirePositive(replayRetention, "replayRetention");
    if (minimumValidity.compareTo(maximumTtl) > 0) {
      throw new IllegalArgumentException("minimumValidity must not exceed maximumTtl");
    }
    if (replayRetention.compareTo(maximumTtl) > 0) {
      throw new IllegalArgumentException("replayRetention must not exceed maximumTtl");
    }
  }

  /** Validates identity and provider state, then atomically binds a jti to one immutable set. */
  public void register(
      McpAccessTokenContext token,
      String tenantHeader,
      String actorHeader,
      List<ProviderBindingGrant> bindings) {
    register(token, tenantHeader, actorHeader, bindings, null);
  }

  /** Validates identity and stores exact bindings plus optional delegated node authority. */
  public void register(
      McpAccessTokenContext token,
      String tenantHeader,
      String actorHeader,
      List<ProviderBindingGrant> bindings,
      DelegatedCapabilityAuthority delegatedAuthority) {
    Objects.requireNonNull(token, "token must not be null");
    if (!token.tenantId().equals(tenantHeader) || !token.subject().equals(actorHeader)) {
      throw new McpGrantRejectedException(
          McpGrantRejectedException.Reason.IDENTITY_MISMATCH,
          "request identity does not match signed token identity");
    }

    Instant now = clock.instant();
    Duration remaining = Duration.between(now, token.expiresAt());
    if (remaining.compareTo(minimumValidity) < 0) {
      throw new McpGrantRejectedException(
          McpGrantRejectedException.Reason.TOKEN_VALIDITY,
          "exchanged token has insufficient remaining validity");
    }
    if (remaining.compareTo(maximumTtl) > 0) {
      throw new McpGrantRejectedException(
          McpGrantRejectedException.Reason.TOKEN_VALIDITY,
          "exchanged token validity exceeds the maximum grant lifetime");
    }

    List<ProviderBindingGrant> immutableBindings = List.copyOf(bindings);
    McpGrantAuthorization authorization =
        new McpGrantAuthorization(
            token.tenantId(),
            token.subject(),
            token.expiresAt(),
            immutableBindings,
            delegatedAuthority);
    verifier.verify(token.tenantId(), token.subject(), immutableBindings);

    Duration storageTtl = remaining.plus(replayRetention);
    if (store.putIfAbsent(token.tokenId(), authorization, storageTtl)) {
      return;
    }
    if (store.find(token.tokenId()).filter(authorization::equals).isPresent()) {
      return;
    }
    throw new McpGrantRejectedException(
        McpGrantRejectedException.Reason.TOKEN_ALREADY_BOUND,
        "access token jti is already bound to different provider resources");
  }

  /** Loads a grant only when its stored identity and expiry exactly match the validated token. */
  public Optional<McpGrantAuthorization> findAuthorization(McpAccessTokenContext token) {
    Objects.requireNonNull(token, "token must not be null");
    Instant now = clock.instant();
    if (!token.expiresAt().isAfter(now)) {
      return Optional.empty();
    }
    return store
        .find(token.tokenId())
        .filter(authorization -> authorization.expiresAt().isAfter(now))
        .filter(authorization -> authorization.expiresAt().equals(token.expiresAt()))
        .filter(authorization -> authorization.tenantId().equals(token.tenantId()))
        .filter(authorization -> authorization.actorId().equals(token.subject()));
  }

  private static Duration requirePositive(Duration value, String field) {
    Objects.requireNonNull(value, field + " must not be null");
    if (value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(field + " must be positive");
    }
    return value;
  }
}
