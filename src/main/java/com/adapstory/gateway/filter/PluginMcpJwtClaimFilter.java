package com.adapstory.gateway.filter;

import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

/**
 * Фильтр валидации JWT claims для MCP маршрутов.
 *
 * <p>Проверяет, что plugin slug из пути /internal/plugins/{slug}/mcp содержится в JWT claim
 * plugin_tools[]. Извлекает tenant context и устанавливает атрибуты для downstream обработки.
 * Возвращает 403 при отсутствии slug в plugin_tools, 401 при отсутствии authentication context.
 */
@Component
public class PluginMcpJwtClaimFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(PluginMcpJwtClaimFilter.class);

  /** Request attribute: list of authorized plugin tool slugs from JWT claim. */
  public static final String PLUGIN_TOOLS_ATTR = "pluginTools";

  /** Request attribute: tenant ID for MCP dispatch (set after authorization). */
  public static final String MCP_TENANT_ID_ATTR = "mcpTenantId";

  /** Request attribute: validated plugin slug for MCP dispatch. */
  public static final String MCP_PLUGIN_SLUG_ATTR = "mcpPluginSlug";

  private static final Pattern MCP_PATH_PATTERN =
      Pattern.compile("^/internal/plugins/([a-zA-Z0-9][a-zA-Z0-9-]*)/mcp$");

  private static final String ERROR_CODE = "MCP_TOOL_UNAUTHORIZED";
  private static final String METRIC_DENIED = "plugin_gateway_mcp_denied_total";
  private static final String METRIC_ALLOWED = "plugin_gateway_mcp_allowed_total";

  private final ObjectMapper objectMapper;
  private final MeterRegistry meterRegistry;

  public PluginMcpJwtClaimFilter(ObjectMapper objectMapper, MeterRegistry meterRegistry) {
    this.objectMapper = objectMapper;
    this.meterRegistry = meterRegistry;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    // Step 1: Verify authentication context exists
    PluginSecurityContext ctx =
        (PluginSecurityContext) request.getAttribute(PluginAuthFilter.PLUGIN_SECURITY_CONTEXT_ATTR);

    if (ctx == null) {
      log.warn("MCP request without authentication context: {}", request.getRequestURI());
      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          401,
          "Unauthorized",
          "Authentication required for MCP tool access",
          Map.of());
      return;
    }

    // Step 2: Extract slug from path
    String slug = extractSlug(request.getRequestURI());
    if (slug == null) {
      log.warn("Cannot extract plugin slug from MCP path: {}", request.getRequestURI());
      GatewayErrorWriter.writeError(
          objectMapper, response, request, 400, "Bad Request", "Invalid MCP path format", Map.of());
      return;
    }

    // Step 3: Get plugin_tools from request attribute (set by PluginAuthFilter from JWT claims)
    @SuppressWarnings("unchecked")
    List<String> pluginTools = (List<String>) request.getAttribute(PLUGIN_TOOLS_ATTR);

    if (pluginTools == null || !pluginTools.contains(slug)) {
      log.warn(
          "MCP tool access denied: slug={}, pluginId={}, pluginTools={}",
          slug,
          ctx.pluginId(),
          pluginTools);
      meterRegistry.counter(METRIC_DENIED, "slug", slug).increment();

      GatewayErrorWriter.writeError(
          objectMapper,
          response,
          request,
          403,
          "Forbidden",
          String.format("Plugin tool '%s' is not authorized for this session", slug),
          Map.of("slug", slug, "pluginId", ctx.pluginId(), "error_code", ERROR_CODE));
      return;
    }

    // Step 4: Set downstream attributes
    request.setAttribute(MCP_TENANT_ID_ATTR, ctx.tenantId());
    request.setAttribute(MCP_PLUGIN_SLUG_ATTR, slug);

    meterRegistry.counter(METRIC_ALLOWED, "slug", slug).increment();

    log.debug("MCP tool access authorized: slug={}, pluginId={}", slug, ctx.pluginId());
    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !request.getRequestURI().startsWith("/internal/plugins/");
  }

  /**
   * Извлекает plugin slug из MCP пути.
   *
   * @param path URI запроса (e.g., /internal/plugins/course-builder/mcp)
   * @return slug или null если путь не соответствует MCP шаблону
   */
  static String extractSlug(String path) {
    Matcher matcher = MCP_PATH_PATTERN.matcher(path);
    if (matcher.matches()) {
      return matcher.group(1);
    }
    return null;
  }
}
