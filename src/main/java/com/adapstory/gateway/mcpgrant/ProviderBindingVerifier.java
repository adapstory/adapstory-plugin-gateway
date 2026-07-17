package com.adapstory.gateway.mcpgrant;

import java.util.List;

/** Revalidates one complete binding set against Plugin Lifecycle before authorization. */
public interface ProviderBindingVerifier {

  void verify(String tenantId, String actorId, List<ProviderBindingGrant> bindings);
}
