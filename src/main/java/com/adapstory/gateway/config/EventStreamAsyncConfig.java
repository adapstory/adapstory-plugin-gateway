package com.adapstory.gateway.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.concurrent.RejectedExecutionException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Bounded executor and timeout policy for long-lived servlet event streams. */
@Configuration
public class EventStreamAsyncConfig implements WebMvcConfigurer {

  private final EventStreamAsyncProperties properties;
  private final Counter rejectedStreams;
  private ThreadPoolTaskExecutor executor;

  public EventStreamAsyncConfig(
      EventStreamAsyncProperties properties, MeterRegistry meterRegistry) {
    this.properties = properties;
    this.rejectedStreams =
        Counter.builder("plugin_gateway_event_stream_executor_rejections_total")
            .description("Event streams rejected because the bounded servlet executor is full")
            .register(meterRegistry);
  }

  /** Returns the managed, bounded executor used by Spring MVC streaming responses. */
  @Bean(name = "eventStreamTaskExecutor")
  public synchronized ThreadPoolTaskExecutor eventStreamTaskExecutor() {
    if (executor == null) {
      executor = new ThreadPoolTaskExecutor();
      executor.setCorePoolSize(properties.getCorePoolSize());
      executor.setMaxPoolSize(properties.getMaxPoolSize());
      executor.setQueueCapacity(properties.getQueueCapacity());
      executor.setThreadNamePrefix("event-stream-");
      executor.setWaitForTasksToCompleteOnShutdown(true);
      executor.setAwaitTerminationSeconds(properties.getAwaitTerminationSeconds());
      executor.setRejectedExecutionHandler(
          (task, pool) -> {
            rejectedStreams.increment();
            throw new RejectedExecutionException(
                "Event-stream capacity is exhausted; rejecting the request");
          });
    }
    return executor;
  }

  @Override
  public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
    configurer.setTaskExecutor(eventStreamTaskExecutor());
    // SSE lifetime is governed by client disconnect, upstream completion, and ingress policy.
    configurer.setDefaultTimeout(0L);
  }
}
