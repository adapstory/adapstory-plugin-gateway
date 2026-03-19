package com.adapstory.gateway.config;

import java.util.concurrent.Executor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Конфигурация managed executor для асинхронных задач Plugin Gateway.
 *
 * <p>webhookExecutor используется для асинхронной диспетчеризации webhook-ов. Managed executor
 * обеспечивает graceful shutdown: дожидается завершения in-flight webhook dispatch при остановке
 * приложения.
 */
@Configuration
class AsyncConfig {

  @Bean("webhookExecutor")
  Executor webhookExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(2);
    executor.setMaxPoolSize(8);
    executor.setQueueCapacity(50);
    executor.setThreadNamePrefix("webhook-dispatch-");
    executor.setWaitForTasksToCompleteOnShutdown(true);
    executor.setAwaitTerminationSeconds(30);
    return executor;
  }
}
