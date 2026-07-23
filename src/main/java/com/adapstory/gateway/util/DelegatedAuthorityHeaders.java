package com.adapstory.gateway.util;

/** Canonical trusted headers and servlet attributes for delegated node authority. */
public final class DelegatedAuthorityHeaders {

  public static final String HEADER_RUN_ID = "X-PDLC-Run-Id";
  public static final String HEADER_NODE_ID = "X-PDLC-Node-Id";
  public static final String HEADER_POLICY_VERSION = "X-Adapstory-Capability-Policy-Version";
  public static final String HEADER_GRANT_ID = "X-Adapstory-Capability-Grant-Id";
  public static final String HEADER_CAPABILITIES = "X-Adapstory-Capability-Grant";

  public static final String TRUSTED_RUN_ID_ATTR = "trustedPdlcRunId";
  public static final String TRUSTED_NODE_ID_ATTR = "trustedPdlcNodeId";
  public static final String TRUSTED_POLICY_VERSION_ATTR = "trustedCapabilityPolicyVersion";
  public static final String TRUSTED_GRANT_ID_ATTR = "trustedCapabilityGrantId";
  public static final String TRUSTED_CAPABILITIES_ATTR = "trustedCapabilityGrant";

  private DelegatedAuthorityHeaders() {}
}
