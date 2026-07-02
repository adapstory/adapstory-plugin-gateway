package com.adapstory.gateway.filter;

import com.adapstory.gateway.dto.PluginSecurityContext;
import java.io.Serial;
import java.util.Collection;
import java.util.Objects;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/** Токен аутентификации плагина для Spring Security. */
public class PluginAuthenticationToken extends AbstractAuthenticationToken {

  @Serial private static final long serialVersionUID = 1L;

  private final PluginSecurityContext pluginContext;

  public PluginAuthenticationToken(
      PluginSecurityContext pluginContext, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.pluginContext = pluginContext;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public PluginSecurityContext getPrincipal() {
    return pluginContext;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof PluginAuthenticationToken that)) {
      return false;
    }
    return isAuthenticated() == that.isAuthenticated()
        && Objects.equals(pluginContext, that.pluginContext)
        && Objects.equals(getAuthorities(), that.getAuthorities());
  }

  @Override
  public int hashCode() {
    return Objects.hash(pluginContext, getAuthorities(), isAuthenticated());
  }
}
