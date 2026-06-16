package com.adapstory.gateway.routing;

import org.springframework.http.HttpHeaders;

interface WebhookDeliveryPort {

  void send(String pluginPodUrl, byte[] payload, HttpHeaders headers);
}
