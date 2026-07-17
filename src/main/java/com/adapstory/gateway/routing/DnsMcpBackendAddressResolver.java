package com.adapstory.gateway.routing;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import org.springframework.stereotype.Component;

/** JVM DNS adapter for Kubernetes headless-service A/AAAA records. */
@Component
final class DnsMcpBackendAddressResolver implements McpBackendAddressResolver {

  @Override
  public List<InetAddress> resolve(String host) throws UnknownHostException {
    return Arrays.asList(InetAddress.getAllByName(host));
  }
}
