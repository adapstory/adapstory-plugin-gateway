package com.adapstory.gateway.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Capacity limits for long-lived servlet event-stream requests. */
@Validated
@ConfigurationProperties(prefix = "gateway.event-stream")
public class EventStreamAsyncProperties {

  @Positive private int corePoolSize = 4;
  @Positive private int maxPoolSize = 32;
  @PositiveOrZero private int queueCapacity = 0;
  @Positive private int awaitTerminationSeconds = 30;

  public int getCorePoolSize() {
    return corePoolSize;
  }

  public void setCorePoolSize(int corePoolSize) {
    this.corePoolSize = corePoolSize;
  }

  public int getMaxPoolSize() {
    return maxPoolSize;
  }

  public void setMaxPoolSize(int maxPoolSize) {
    this.maxPoolSize = maxPoolSize;
  }

  public int getQueueCapacity() {
    return queueCapacity;
  }

  public void setQueueCapacity(int queueCapacity) {
    this.queueCapacity = queueCapacity;
  }

  public int getAwaitTerminationSeconds() {
    return awaitTerminationSeconds;
  }

  public void setAwaitTerminationSeconds(int awaitTerminationSeconds) {
    this.awaitTerminationSeconds = awaitTerminationSeconds;
  }

  @AssertTrue(message = "max-pool-size must be greater than or equal to core-pool-size")
  public boolean isPoolRangeValid() {
    return maxPoolSize >= corePoolSize;
  }
}
