package com.adapstory.gateway.event;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.annotation.KafkaListener;

class PermissionCacheInvalidationListenerKafkaContractTest {

  @Test
  @DisplayName("permission revocation listener auto-startup is configurable")
  void should_makePermissionRevocationListenerAutoStartupConfigurable() throws Exception {
    Method method =
        PermissionCacheInvalidationListener.class.getDeclaredMethod(
            "onPluginPermissionsRevoked", String.class, String.class, String.class);

    KafkaListener listener = method.getAnnotation(KafkaListener.class);

    assertThat(listener).isNotNull();
    assertThat(listener.autoStartup())
        .isEqualTo("${gateway.kafka.listeners.permission-revocation.auto-startup:true}");
  }
}
