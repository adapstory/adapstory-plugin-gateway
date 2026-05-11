package com.adapstory.gateway.util;

import com.adapstory.commons.header.IntegrationHeaders;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.MDC;
import org.springframework.http.HttpRequest;

/**
 * Shared utilities for BC-02 fetch clients.
 *
 * <p>Eliminates duplication of plugin ID validation, header propagation, and fallback interceptor
 * logic between {@code InstalledPluginFetchClient} and {@code PermissionFetchClient} (SOLID audit
 * finding #5).
 */
public final class FetchClientUtils {

  /** Acceptable plugin ID format: tri-part (vendor.category.name) or similar. */
  public static final Pattern PLUGIN_ID_PATTERN =
      Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9._-]{1,123}[a-zA-Z0-9]$");

  public static final String HEADER_SOURCE_SERVICE = "plugin-gateway";

  private FetchClientUtils() {}

  /**
   * Validates a plugin ID against the accepted format (tri-part or UUID).
   *
   * @param pluginId the plugin ID to validate
   * @throws NullPointerException if pluginId is null
   * @throws IllegalArgumentException if pluginId is blank or does not match format
   */
  public static void validatePluginId(String pluginId) {
    Objects.requireNonNull(pluginId, "pluginId must not be null");
    if (pluginId.isBlank()) {
      throw new IllegalArgumentException("pluginId must not be blank");
    }
    if (!PLUGIN_ID_PATTERN.matcher(pluginId).matches()) {
      throw new IllegalArgumentException(
          "pluginId format invalid (expected tri-part or UUID): " + pluginId);
    }
  }

  /**
   * Propagates a header value, falling back to a default when the current value is null or blank.
   *
   * @param request outgoing HTTP request
   * @param headerName header name to set
   * @param currentValue current value (may be null)
   * @param defaultValue fallback value when current is null/blank
   */
  public static void propagateHeader(
      HttpRequest request, String headerName, String currentValue, String defaultValue) {
    String value = currentValue != null && !currentValue.isBlank() ? currentValue : defaultValue;
    request.getHeaders().set(headerName, value);
  }

  /**
   * Creates a fallback header interceptor that propagates request-id, correlation-id, user-id, and
   * source-service headers when no {@code ServiceTokenPort} is available.
   *
   * @return a {@link org.springframework.http.client.ClientHttpRequestInterceptor} lambda
   */
  public static org.springframework.http.client.ClientHttpRequestInterceptor
      fallbackHeaderInterceptor() {
    return (request, body, execution) -> {
      propagateHeader(
          request,
          IntegrationHeaders.HEADER_REQUEST_ID,
          MDC.get(IntegrationHeaders.REQUEST_ID),
          UUID.randomUUID().toString());
      propagateHeader(
          request,
          IntegrationHeaders.HEADER_CORRELATION_ID,
          MDC.get(IntegrationHeaders.CORRELATION_ID),
          UUID.randomUUID().toString());
      request
          .getHeaders()
          .set(IntegrationHeaders.HEADER_USER_ID, "service:" + HEADER_SOURCE_SERVICE);
      request.getHeaders().set(IntegrationHeaders.HEADER_SOURCE_SERVICE, HEADER_SOURCE_SERVICE);
      return execution.execute(request, body);
    };
  }
}
