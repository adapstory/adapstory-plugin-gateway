package com.adapstory.gateway.filter;

import com.adapstory.commons.header.IntegrationIdValidator;
import com.adapstory.commons.header.IntegrationHeaders;
import com.adapstory.gateway.dto.PluginSecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Фильтр внедрения обязательных заголовков.
 *
 * <p>Инжектирует: request-id (UUID), correlation-id (из входящего или UUID),
 * user-id=plugin:{pluginId}. Пробрасывает существующий correlation-id и сохраняет исходного
 * пользователя отдельно в X-Adapstory-User-Id, когда он пришёл извне.
 */
@Component
@Order(3)
public class HeaderInjectionFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String requestId = request.getHeader(IntegrationHeaders.HEADER_REQUEST_ID);
    if (!IntegrationIdValidator.isValidUuidV4OrV7(requestId)) {
      requestId = UUID.randomUUID().toString();
    }

    String correlationId = request.getHeader(IntegrationHeaders.HEADER_CORRELATION_ID);
    if (correlationId == null || correlationId.isBlank()) {
      correlationId = UUID.randomUUID().toString();
    }

    String userId = resolveUserId(request);
    String originalUserId = resolveOriginalUserId(request, userId);

    MDC.put(IntegrationHeaders.REQUEST_ID, requestId);
    MDC.put(IntegrationHeaders.CORRELATION_ID, correlationId);
    MDC.put(IntegrationHeaders.USER_ID, userId);
    putIfPresent(IntegrationHeaders.ADAPSTORY_USER_ID, originalUserId);

    try {
      MandatoryHeadersRequestWrapper wrappedRequest =
          new MandatoryHeadersRequestWrapper(request, requestId, correlationId, userId, originalUserId);

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

  private String resolveOriginalUserId(HttpServletRequest request, String localUserId) {
    String explicitOriginal = request.getHeader(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID);
    if (explicitOriginal != null && !explicitOriginal.isBlank()) {
      return explicitOriginal;
    }
    String legacyUserId = request.getHeader(IntegrationHeaders.HEADER_USER_ID);
    if (legacyUserId != null && !legacyUserId.isBlank() && !legacyUserId.equals(localUserId)) {
      return legacyUserId;
    }
    return null;
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
        String userId,
        String originalUserId) {
      super(request);
      this.injectedHeaders = new LinkedHashMap<>();
      this.injectedHeaders.put(IntegrationHeaders.HEADER_REQUEST_ID, requestId);
      this.injectedHeaders.put(IntegrationHeaders.HEADER_CORRELATION_ID, correlationId);
      this.injectedHeaders.put(IntegrationHeaders.HEADER_USER_ID, userId);
      if (originalUserId != null && !originalUserId.isBlank()) {
        this.injectedHeaders.put(IntegrationHeaders.HEADER_ADAPSTORY_USER_ID, originalUserId);
      }
    }

    @Override
    public String getHeader(String name) {
      String injected = injectedHeaders.get(name);
      return injected != null ? injected : super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
      String injected = injectedHeaders.get(name);
      if (injected != null) {
        return Collections.enumeration(List.of(injected));
      }
      return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
      List<String> names = new java.util.ArrayList<>(Collections.list(super.getHeaderNames()));
      for (String key : injectedHeaders.keySet()) {
        if (!names.contains(key)) {
          names.add(key);
        }
      }
      return Collections.enumeration(names);
    }
  }
}
