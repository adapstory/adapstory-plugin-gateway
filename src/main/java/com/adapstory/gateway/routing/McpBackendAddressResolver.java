package com.adapstory.gateway.routing;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/** Resolves all concrete pod addresses behind a required headless provider service. */
@FunctionalInterface
interface McpBackendAddressResolver {

  List<InetAddress> resolve(String host) throws UnknownHostException;
}
