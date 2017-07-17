package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import org.apache.sentry.core.common.Authorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 *
 */
class WildcardPolicy {
  private final List<WildcardAuthorizable> authorizables;
  private final ActionFactory.Action allowedAction;

  WildcardPolicy(TSentryPrivilege privilege) {
    List<TAuthorizable> tAuthorizables = privilege.getAuthorizables();

    allowedAction = new ActionFactory.Action(privilege.getAction());
    if (tAuthorizables.isEmpty()) {
      authorizables = Collections.emptyList();
      return;
    }

    authorizables = new ArrayList<>(tAuthorizables.size());
    for (TAuthorizable authorizable : tAuthorizables) {
      authorizables.add(new WildcardAuthorizable(authorizable));
    }
  }

  boolean isAllowed(List<? extends Authorizable> entityAuthorizables, ActionFactory.Action action) {
    if (authorizables.isEmpty()) {
      return false;
    }

    // Authorizable parts have to match exactly
    if (authorizables.size() != entityAuthorizables.size()) {
      return false;
    }

    int index = 0;
    while (index < authorizables.size()) {
      if (!authorizables.get(index).matches(entityAuthorizables.get(index))) {
        return false;
      }
      ++index;
    }

    // Check action
    if (!allowedAction.implies(action)) {
      return false;
    }

    // Both authorizables and action matched, hence the action is allowed on this entity
    return true;
  }

  boolean isVisible(List<Authorizable> entityAuthorizables) {
    if (authorizables.isEmpty()) {
      return false;
    }

    // Entity should be a parent or equal to the authorizable in the policy
    if (entityAuthorizables.size() > authorizables.size()) {
      return false;
    }

    int index = 0;
    while (index < entityAuthorizables.size()) {
      if (!authorizables.get(index).matches(entityAuthorizables.get(index))) {
        return false;
      }
      ++index;
    }

    // Entity is a parent or the same as the authorizable in the policy,
    // hence the entity is visible
    return true;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    WildcardPolicy that = (WildcardPolicy) o;
    return Objects.equals(authorizables, that.authorizables) &&
      Objects.equals(allowedAction, that.allowedAction);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorizables, allowedAction);
  }

  @Override
  public String toString() {
    return "WildcardPolicy{" +
      "authorizables=" + authorizables +
      ", allowedAction=" + allowedAction +
      '}';
  }
}
