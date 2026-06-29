package com.adapstory.gateway.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Browser/BFF-originated user-token fallback for first-party plugin REST routes. */
@ConfigurationProperties(prefix = "gateway.bff-user-jwt")
public class BffUserJwtProperties {

  private boolean enabled = true;
  private List<String> audiences =
      new ArrayList<>(List.of("adapstory-bff-school", "adapstory-api", "lms-client", "account"));
  private List<String> allowedRoles =
      new ArrayList<>(
          List.of(
              "SCHOOL_OPERATOR",
              "TENANT_OWNER",
              "METHODIST",
              "INSTRUCTOR",
              "PLATFORM_ADMIN",
              "SUPER_ADMIN",
              "school_operator",
              "tenant_owner",
              "methodist",
              "instructor",
              "platform_admin",
              "super_admin",
              "adapstory:school-operator",
              "adapstory:methodist",
              "adapstory:instructor",
              "adapstory:superadmin"));

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public List<String> getAudiences() {
    return audiences;
  }

  public void setAudiences(List<String> audiences) {
    this.audiences = audiences == null ? new ArrayList<>() : new ArrayList<>(audiences);
  }

  public List<String> getAllowedRoles() {
    return allowedRoles;
  }

  public void setAllowedRoles(List<String> allowedRoles) {
    this.allowedRoles = allowedRoles == null ? new ArrayList<>() : new ArrayList<>(allowedRoles);
  }
}
