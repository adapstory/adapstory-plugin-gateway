package com.adapstory.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;

class EventStreamAsyncConfigTest {

  @Test
  void configuresNoServletTimeoutAndTheBoundedManagedExecutor() {
    EventStreamAsyncProperties properties = new EventStreamAsyncProperties();
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    EventStreamAsyncConfig configuration = new EventStreamAsyncConfig(properties, registry);
    ThreadPoolTaskExecutor executor = configuration.eventStreamTaskExecutor();
    executor.initialize();
    AsyncSupportConfigurer asyncSupport = mock(AsyncSupportConfigurer.class);

    configuration.configureAsyncSupport(asyncSupport);

    verify(asyncSupport).setDefaultTimeout(0L);
    verify(asyncSupport).setTaskExecutor(executor);
    assertThat(executor.getCorePoolSize()).isEqualTo(properties.getCorePoolSize());
    assertThat(executor.getMaxPoolSize()).isEqualTo(properties.getMaxPoolSize());
    executor.shutdown();
  }

  @Test
  void rejectsOverloadInsteadOfCreatingUnboundedStreamingThreads() throws Exception {
    EventStreamAsyncProperties properties = new EventStreamAsyncProperties();
    properties.setCorePoolSize(1);
    properties.setMaxPoolSize(1);
    properties.setQueueCapacity(0);
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    EventStreamAsyncConfig configuration = new EventStreamAsyncConfig(properties, registry);
    ThreadPoolTaskExecutor executor = configuration.eventStreamTaskExecutor();
    executor.initialize();
    CountDownLatch started = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);

    executor.execute(
        () -> {
          started.countDown();
          try {
            release.await();
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
          }
        });
    assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();

    assertThatThrownBy(() -> executor.execute(() -> {})).isInstanceOf(TaskRejectedException.class);
    assertThat(
            registry.get("plugin_gateway_event_stream_executor_rejections_total").counter().count())
        .isEqualTo(1.0);

    release.countDown();
    executor.shutdown();
  }
}
