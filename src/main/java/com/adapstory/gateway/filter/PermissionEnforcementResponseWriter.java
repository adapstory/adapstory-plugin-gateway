package com.adapstory.gateway.filter;

import com.adapstory.gateway.dto.PluginSecurityContext;
import com.adapstory.gateway.util.GatewayErrorWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

final class PermissionEnforcementResponseWriter {
  private static final String ERROR_FORBIDDEN = "Forbidden";
  private static final String DETAIL_PLUGIN_ID = "pluginId";

  private final ObjectMapper objectMapper;

  PermissionEnforcementResponseWriter(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  void writeMissingPermission(
      HttpServletRequest request, HttpServletResponse response, PluginSecurityContext pluginContext)
      throws IOException {
    GatewayErrorWriter.writeError(
        objectMapper,
        response,
        request,
        403,
        ERROR_FORBIDDEN,
        "No permission mapping configured for this route",
        buildDetails(pluginContext, null));
  }

  void writeJwtDenied(
      HttpServletRequest request,
      HttpServletResponse response,
      PluginSecurityContext pluginContext,
      String requiredPermission)
      throws IOException {
    GatewayErrorWriter.writeError(
        objectMapper,
        response,
        request,
        403,
        ERROR_FORBIDDEN,
        String.format(
            "Plugin '%s' does not have permission '%s'",
            extractShortPluginId(pluginContext.pluginId()), requiredPermission),
        buildDetails(pluginContext, requiredPermission));
  }

  void writeUnavailable(
      HttpServletRequest request, HttpServletResponse response, String pluginId, String errorCode)
      throws IOException {
    Map<String, Object> details = new LinkedHashMap<>();
    details.put(DETAIL_PLUGIN_ID, pluginId);
    details.put("errorCode", errorCode);
    GatewayErrorWriter.writeError(
        objectMapper,
        response,
        request,
        503,
        "Service Unavailable",
        "Unable to verify plugin permissions",
        details);
  }

  void writeManifestDenied(
      HttpServletRequest request,
      HttpServletResponse response,
      String pluginId,
      String requiredPermission,
      String errorCode)
      throws IOException {
    Map<String, Object> details = new LinkedHashMap<>();
    details.put(DETAIL_PLUGIN_ID, pluginId);
    details.put("requiredPermission", requiredPermission);
    details.put("errorCode", errorCode);
    GatewayErrorWriter.writeError(
        objectMapper,
        response,
        request,
        403,
        ERROR_FORBIDDEN,
        String.format("Permission '%s' has been revoked", requiredPermission),
        details);
  }

  private String extractShortPluginId(String fullPluginId) {
    if (fullPluginId == null) {
      return "unknown";
    }
    int lastDot = fullPluginId.lastIndexOf('.');
    return lastDot >= 0 ? fullPluginId.substring(lastDot + 1) : fullPluginId;
  }

  private Map<String, Object> buildDetails(
      PluginSecurityContext pluginContext, String requiredPermission) {
    Map<String, Object> details = new LinkedHashMap<>();
    if (pluginContext != null) {
      details.put(DETAIL_PLUGIN_ID, pluginContext.pluginId());
      if (requiredPermission != null) {
        details.put("requiredPermission", requiredPermission);
      }
    }
    return details;
  }
}
