package com.adapstory.gateway.filter;

import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.commons.header.IntegrationIdValidator;
import com.adapstory.gateway.dto.PluginSecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Фильтр внедрения обязательных заголовков.
 *
 * <p>Инжектирует: request-id (UUID), correlation-id (из входящего или UUID),
 * user-id=plugin:{pluginId}, JWT tenant and signed actor identity. Caller-controlled identity
 * headers are removed case-insensitively before the request reaches a proxy adapter.
 */
@Component
@Order(3)
public class HeaderInjectionFilter extends OncePerRequestFilter {

  public static final String TRUSTED_TENANT_ID_ATTR = "trustedTenantId";
  public static final String TRUSTED_USER_ID_ATTR = "trustedUserId";
  public static final String TRUSTED_ADAPSTORY_USER_ID_ATTR = "trustedAdapstoryUserId";
  public static final String TRUSTED_USER_ROLES_ATTR = "trustedUserRoles";
  public static final String HEADER_USER_ROLES = "X-User-Roles";

  private static final Set<String> PROTECTED_IDENTITY_HEADERS =
      Set.of(
          IntegrationHeaders.HEADER_TENANT_ID.toLowerCase(java.util.Locale.ROOT),
          IntegrationHeaders.HEADER_USER_ID.toLowerCase(java.util.Locale.ROOT),
          IntegrationHeaders.HEADER_ADAPSTORY_USER_ID.toLowerCase(java.util.Locale.ROOT),
          HEADER_USER_ROLES.toLowerCase(java.util.Locale.ROOT));

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String requestId =
        IntegrationIdValidator.normalizeUuidV4OrV7(
            request.getHeader(IntegrationHeaders.HEADER_REQUEST_ID));
    if (requestId == null) {
      requestId = com.adapstory.commons.id.Uuid7.randomUuid().toString();
    }

    String correlationId =
        IntegrationIdValidator.normalizeUuidV4OrV7(
            request.getHeader(IntegrationHeaders.HEADER_CORRELATION_ID));
    if (correlationId == null) {
      correlationId = com.adapstory.commons.id.Uuid7.randomUuid().toString();
    }

    String userId = resolveUserId(request);
    String tenantId = resolveTenantId(request);
    String actorId = resolveAuthenticatedActorId(request);
    String roles = attributeString(request, PluginAuthFilter.AUTHENTICATED_USER_ROLES_ATTR);

    setTrustedAttribute(request, TRUSTED_TENANT_ID_ATTR, tenantId);
    setTrustedAttribute(request, TRUSTED_USER_ID_ATTR, userId);
    setTrustedAttribute(request, TRUSTED_ADAPSTORY_USER_ID_ATTR, actorId);
    setTrustedAttribute(request, TRUSTED_USER_ROLES_ATTR, roles);

    MDC.put(IntegrationHeaders.REQUEST_ID, requestId);
    MDC.put(IntegrationHeaders.CORRELATION_ID, correlationId);
    MDC.put(IntegrationHeaders.USER_ID, userId);
    putIfPresent(IntegrationHeaders.ADAPSTORY_USER_ID, actorId);

    try {
      MandatoryHeadersRequestWrapper wrappedRequest =
          new MandatoryHeadersRequestWrapper(
              request, requestId, correlationId, tenantId, userId, actorId, roles);

      response.setHeader(IntegrationHeaders.HEADER_REQUEST_ID, requestId);
      response.setHeader(IntegrationHeaders.HEADER_RESPONSE_ID, requestId);
      response.setHeader(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);

      filterChain.doFilter(wrappedRequest, response);
    } finally {
      MDC.remove(IntegrationHeaders.REQUEST_ID);
      MDC.remove(IntegrationHeaders.CORRELATION_ID);
      MDC.remove(IntegrationHeaders.USER_ID);
      MDC.remove(IntegrationHeaders.ADAPSTORY_USER_ID);
    }
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return request.getRequestURI().startsWith("/actuator/");
  }

  private String resolveUserId(HttpServletRequest request) {
    PluginSecurityContext pluginContext =
        (PluginSecurityContext) request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);
    if (pluginContext != null) {
      return "plugin:" + pluginContext.pluginId();
    }
    return "anonymous";
  }

  private String resolveTenantId(HttpServletRequest request) {
    PluginSecurityContext pluginContext =
        (PluginSecurityContext) request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);
    return pluginContext == null ? null : pluginContext.tenantId();
  }

  private String resolveAuthenticatedActorId(HttpServletRequest request) {
    return attributeString(request, PluginAuthFilter.AUTHENTICATED_ACTOR_ID_ATTR);
  }

  private static String attributeString(HttpServletRequest request, String name) {
    Object value = request.getAttribute(name);
    return value instanceof String string && !string.isBlank() ? string : null;
  }

  private static void setTrustedAttribute(HttpServletRequest request, String name, String value) {
    if (value != null && !value.isBlank()) {
      request.setAttribute(name, value);
    }
  }

  private void putIfPresent(String key, String value) {
    if (value != null && !value.isBlank()) {
      MDC.put(key, value);
    }
  }

  /** Обёртка запроса, добавляющая обязательные заголовки. */
  private static class MandatoryHeadersRequestWrapper extends HttpServletRequestWrapper {

    private final Map<String, String> injectedHeaders;

    MandatoryHeadersRequestWrapper(
        HttpServletRequest request,
        String requestId,
        String correlationId,
        String tenantId,
        String userId,
        String actorId,
        String roles) {
      super(request);
      this.injectedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
      this.injectedHeaders.put(IntegrationHeaders.HEADER_REQUEST_ID, requestId);
      this.injectedHeaders.put(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);
      if (tenantId != null && !tenantId.isBlank()) {
        this.injectedHeaders.put(IntegrationHeaders.HEADER_TENANT_ID, tenantId);
      }
      this.injectedHeaders.put(IntegrationHeaders.HEADER_USER_ID, userId);
      if (actorId != null && !actorId.isBlank()) {
        this.injectedHeaders.put(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID, actorId);
      }
      if (roles != null && !roles.isBlank()) {
        this.injectedHeaders.put(HEADER_USER_ROLES, roles);
      }
    }

    @Override
    public String getHeader(String name) {
      String injected = injectedHeaders.get(name);
      if (injected != null) {
        return injected;
      }
      return isProtectedIdentityHeader(name) ? null : super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
      String injected = injectedHeaders.get(name);
      if (injected != null) {
        return Collections.enumeration(List.of(injected));
      }
      return isProtectedIdentityHeader(name)
          ? Collections.emptyEnumeration()
          : super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
      List<String> names = new ArrayList<>();
      Set<String> normalizedNames = new HashSet<>();
      for (String name : Collections.list(super.getHeaderNames())) {
        String normalized = name.toLowerCase(java.util.Locale.ROOT);
        if (!PROTECTED_IDENTITY_HEADERS.contains(normalized) && normalizedNames.add(normalized)) {
          names.add(name);
        }
      }
      injectedHeaders.forEach(
          (key, ignored) -> {
            String normalized = key.toLowerCase(java.util.Locale.ROOT);
            if (normalizedNames.add(normalized)) {
              names.add(key);
            }
          });
      return Collections.enumeration(names);
    }

    private static boolean isProtectedIdentityHeader(String name) {
      return name != null
          && PROTECTED_IDENTITY_HEADERS.contains(name.toLowerCase(java.util.Locale.ROOT));
    }
  }
}
