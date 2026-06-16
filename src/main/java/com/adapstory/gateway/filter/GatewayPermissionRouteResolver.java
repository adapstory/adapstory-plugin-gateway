package com.adapstory.gateway.filter;

import com.adapstory.gateway.config.GatewayProperties;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
final class GatewayPermissionRouteResolver {

  private static final String GATEWAY_PREFIX = "/api/bc-02/gateway/v1/api/";

  private final GatewayProperties properties;

  GatewayPermissionRouteResolver(GatewayProperties properties) {
    this.properties = properties;
  }

  String resolveRequiredPermission(String path, String httpMethod) {
    if (!path.startsWith(GATEWAY_PREFIX)) {
      return null;
    }

    String afterPrefix = path.substring(GATEWAY_PREFIX.length());
    int slashIndex = afterPrefix.indexOf('/');
    String routeKey = slashIndex > 0 ? afterPrefix.substring(0, slashIndex) : afterPrefix;

    Map<String, Map<String, String>> routeMappings = properties.permissions().routeMappings();
    Map<String, String> methodMapping = routeMappings.get(routeKey);
    if (methodMapping == null) {
      return null;
    }

    return methodMapping.get(httpMethod.toUpperCase());
  }
}
