package com.trstctl.sdk;

import java.time.Duration;

/** Retry behavior for trstctl requests. */
public final class RetryPolicy {
  public static final RetryPolicy DEFAULT = new RetryPolicy(4, Duration.ofMillis(200), Duration.ofSeconds(5));

  private final int maxAttempts;
  private final Duration baseDelay;
  private final Duration maxDelay;

  public RetryPolicy(int maxAttempts, Duration baseDelay, Duration maxDelay) {
    this.maxAttempts = maxAttempts < 1 ? DEFAULT.maxAttempts : maxAttempts;
    this.baseDelay = baseDelay == null || baseDelay.isZero() || baseDelay.isNegative() ? DEFAULT.baseDelay : baseDelay;
    this.maxDelay = maxDelay == null || maxDelay.isZero() || maxDelay.isNegative() ? DEFAULT.maxDelay : maxDelay;
  }

  public int maxAttempts() {
    return maxAttempts;
  }

  public Duration baseDelay() {
    return baseDelay;
  }

  public Duration maxDelay() {
    return maxDelay;
  }

  Duration delayFor(int attempt, Long retryAfterSeconds) {
    if (retryAfterSeconds != null) {
      return min(Duration.ofSeconds(Math.max(0, retryAfterSeconds)), maxDelay);
    }
    long multiplier = 1L << Math.max(0, Math.min(30, attempt - 1));
    return min(baseDelay.multipliedBy(multiplier), maxDelay);
  }

  private static Duration min(Duration a, Duration b) {
    return a.compareTo(b) <= 0 ? a : b;
  }
}
