package com.adapstory.gateway.util;

import java.util.regex.Pattern;

/**
 * Shared plugin slug/short-ID validation.
 *
 * <p>Eliminates duplication of {@code SLUG_PATTERN} / {@code PLUGIN_SHORT_ID_PATTERN} between
 * {@code McpRouteController} and {@code WebhookDispatcher} (SOLID audit finding #6).
 */
public final class PluginSlugValidator {

  /** Valid plugin slug format: alphanumeric start, may contain hyphens. */
  public static final Pattern SLUG_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9-]*$");

  private PluginSlugValidator() {}

  /**
   * Checks whether the given slug matches the expected format.
   *
   * @param slug plugin slug to validate
   * @return {@code true} if the slug is valid
   */
  public static boolean isValidSlug(String slug) {
    return slug != null && SLUG_PATTERN.matcher(slug).matches();
  }
}
