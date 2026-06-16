package com.adapstory.gateway.filter;

final class PermissionIntersectionResult {

  private enum Status {
    GRANTED,
    JWT_MISSING,
    REVOKED,
    UNAVAILABLE
  }

  private final Status status;
  private final String requiredPermission;
  private final String pluginId;

  private PermissionIntersectionResult(Status status, String requiredPermission, String pluginId) {
    this.status = status;
    this.requiredPermission = requiredPermission;
    this.pluginId = pluginId;
  }

  static PermissionIntersectionResult granted() {
    return new PermissionIntersectionResult(Status.GRANTED, null, null);
  }

  static PermissionIntersectionResult jwtMissing(String requiredPermission) {
    return new PermissionIntersectionResult(Status.JWT_MISSING, requiredPermission, null);
  }

  static PermissionIntersectionResult revoked(String pluginId, String requiredPermission) {
    return new PermissionIntersectionResult(Status.REVOKED, requiredPermission, pluginId);
  }

  static PermissionIntersectionResult unavailable(String pluginId) {
    return new PermissionIntersectionResult(Status.UNAVAILABLE, null, pluginId);
  }

  boolean isGranted() {
    return status == Status.GRANTED;
  }

  boolean isJwtMissing() {
    return status == Status.JWT_MISSING;
  }

  boolean isUnavailable() {
    return status == Status.UNAVAILABLE;
  }

  String getRequiredPermission() {
    return requiredPermission;
  }

  String getPluginId() {
    return pluginId;
  }
}
