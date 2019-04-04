/*
 * Copyright © 2016-2019 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package io.cdap.cdap.security.authorization.sentry.binding;

import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.proto.security.Privilege;
import io.cdap.cdap.proto.security.Role;
import io.cdap.cdap.security.authorization.sentry.binding.conf.AuthConf;
import io.cdap.cdap.security.authorization.sentry.model.ActionFactory;
import io.cdap.cdap.security.authorization.sentry.model.Authorizable;
import io.cdap.cdap.security.spi.authorization.AbstractAuthorizer;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;
import io.cdap.cdap.security.spi.authorization.Authorizer;
import io.cdap.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * This class implements {@link Authorizer} from CDAP and is responsible for interacting with Sentry to manage
 * privileges.
 */
public class SentryAuthorizer extends AbstractAuthorizer {

  private static final Logger LOG = LoggerFactory.getLogger(SentryAuthorizer.class);

  private AuthBinding binding;
  private AuthorizationContext context;

  @Override
  public void initialize(AuthorizationContext context) throws Exception {
    Properties properties = context.getExtensionProperties();
    String sentrySiteUrl = properties.getProperty(AuthConf.SENTRY_SITE_URL);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(AuthConf.SENTRY_SITE_URL),
                                "Path to sentry-site.xml path is not specified in cdap-site.xml. Please provide the " +
                                  "path to sentry-site.xml in cdap-site.xml with property name %s",
                                AuthConf.SENTRY_SITE_URL);
    String sentryAdminGroup = properties.getProperty(AuthConf.SENTRY_ADMIN_GROUP,
                                                     AuthConf.AuthzConfVars.AUTHZ_SENTRY_ADMIN_GROUP.getDefault());
    Preconditions.checkArgument(!sentryAdminGroup.contains(","),
                                "Please provide exactly one Sentry admin group at %s in cdap-site.xml. Found '%s'.",
                                AuthConf.SENTRY_ADMIN_GROUP, sentryAdminGroup);
    String instanceName = properties.containsKey(AuthConf.INSTANCE_NAME) ?
      properties.getProperty(AuthConf.INSTANCE_NAME) :
      AuthConf.AuthzConfVars.getDefault(AuthConf.INSTANCE_NAME);

    int cacheTtlSecs = Integer.parseInt(properties.getProperty(AuthConf.CACHE_TTL_SECS,
                                                               AuthConf.CACHE_TTL_SECS_DEFAULT));
    int cacheMaxEntries = Integer.parseInt(properties.getProperty(AuthConf.CACHE_MAX_ENTRIES,
                                                                  AuthConf.CACHE_MAX_ENTRIES_DEFAULT));

    LOG.info("Configuring SentryAuthorizer with sentry-site.xml at {}, CDAP instance {} and Sentry Admin Group: {}",
             sentrySiteUrl, instanceName, sentryAdminGroup);
    this.binding = new AuthBinding(sentrySiteUrl, instanceName, sentryAdminGroup, cacheTtlSecs, cacheMaxEntries);
    this.context = context;
  }

  @Override
  public void grant(io.cdap.cdap.proto.security.Authorizable authorizable, Principal principal, Set<Action> actions)
    throws Exception {
    LOG.trace("Granting {} on {} to {}", actions, authorizable, principal);
    if (principal.getType().equals(Principal.PrincipalType.ROLE)) {
      binding.grant(authorizable, new Role(principal.getName()), actions, getRequestingUser());
      LOG.trace("Granted {} on {} to {}", actions, authorizable, principal);
    } else {
      throw new IllegalArgumentException(
        String.format("Sentry only supports granting privileges to a '%s'. The given principal '%s' is of unsupported" +
                        " type '%s'.", Principal.PrincipalType.ROLE, principal.getName(), principal.getType()));
    }
  }

  @Override
  public void revoke(io.cdap.cdap.proto.security.Authorizable authorizable, Principal principal, Set<Action> actions)
    throws Exception {
    LOG.trace("Revoking {} on {} to {}", actions, authorizable, principal);
    if (principal.getType().equals(Principal.PrincipalType.ROLE)) {
      binding.revoke(authorizable, new Role(principal.getName()), actions, getRequestingUser());
      LOG.trace("Revoked {} on {} to {}", actions, authorizable, principal);
    } else {
      throw new IllegalArgumentException(
        String.format("Sentry only supports revoking privileges from a '%s'. The given principal '%s' is of " +
                        "unsupported type '%s'.", Principal.PrincipalType.ROLE, principal.getName(),
                      principal.getType()));
    }
  }

  @Override
  public void revoke(io.cdap.cdap.proto.security.Authorizable authorizable) throws Exception {
    LOG.debug("Revoking all privileges on {}", authorizable);
    binding.revoke(authorizable);
    LOG.debug("Revoked all privileges on {}", authorizable);
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    return binding.listPrivileges(principal);
  }

  @Override
  public void createRole(Role role) throws Exception {
    binding.createRole(role, getRequestingUser());
  }

  @Override
  public void dropRole(Role role) throws Exception {
    binding.dropRole(role, getRequestingUser());
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
    binding.addRoleToGroup(role, principal, getRequestingUser());
  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
    binding.removeRoleFromGroup(role, principal, getRequestingUser());
  }

  @Override
  public Set<Role> listRoles(Principal principal) throws Exception {
    Preconditions.checkArgument(principal.getType() != Principal.PrincipalType.ROLE, "The given principal '%s' is of " +
                                  "type '%s'. In Sentry revoke roles can only be listed for '%s' and '%s'",
                                principal.getName(), principal.getType(), Principal.PrincipalType.USER,
                                Principal.PrincipalType.GROUP);
    return binding.listRolesForGroup(principal, getRequestingUser());
  }

  @Override
  public Set<Role> listAllRoles() throws Exception {
    return binding.listAllRoles();
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    checkUserPrincipal(principal);

    Set<WildcardPolicy> policies = binding.getPolicies(principal);
    LOG.debug("Got policies {} for principal {}, entity {} and actions {}", policies, principal, entityId, actions);
    if (policies.isEmpty()) {
      throw new UnauthorizedException(principal, actions, entityId, true);
    }

    List<Authorizable> sentryAuthorizables = new ArrayList<>();
    io.cdap.cdap.proto.security.Authorizable authorizable =
      io.cdap.cdap.proto.security.Authorizable.fromEntityId(entityId);
    binding.toSentryAuthorizables(authorizable.getEntityType(), authorizable, sentryAuthorizables);

    Set<ActionFactory.Action> checkActions = binding.toSentryActions(actions);

    // Check each action against each policy
    Set<ActionFactory.Action> allowedActions = new HashSet<>(actions.size());
    for (ActionFactory.Action sentryAction : checkActions) {
      for (WildcardPolicy policy : policies) {
        if (policy.isAllowed(sentryAuthorizables, sentryAction)) {
          allowedActions.add(sentryAction);
          // no need to check the other policies since this action is allowed by this policy
          break;
        }
      }
    }

    if (!checkActions.equals(allowedActions)) {
      throw new UnauthorizedException(principal, actions, entityId, true);
    }
  }

  @Override
  public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {
    checkUserPrincipal(principal);

    final Set<WildcardPolicy> policies = binding.getPolicies(principal);
    LOG.debug("Got policies {} for principal {}", policies, principal);

    if (policies.isEmpty()) {
      return Collections.emptySet();
    }

    Set<EntityId> visibleEntities = new HashSet<>(entityIds.size());
    for (EntityId entityId : entityIds) {
      List<Authorizable> sentryAuthorizables = new ArrayList<>();
      io.cdap.cdap.proto.security.Authorizable authorizable =
        io.cdap.cdap.proto.security.Authorizable.fromEntityId(entityId);
      binding.toSentryAuthorizables(authorizable.getEntityType(), authorizable, sentryAuthorizables);

      // Even if one policy makes the entity visible, then the entity is visible to the principal
      for (WildcardPolicy policy : policies) {
        if (policy.isVisible(sentryAuthorizables)) {
          visibleEntities.add(entityId);
          break;
        }
      }
    }
    return visibleEntities;
  }

  private void checkUserPrincipal(Principal principal) {
    Preconditions.checkArgument(
      Principal.PrincipalType.USER == principal.getType(),
      "Only support principal type %s for authorization, given principal %s is of type %s",
      Principal.PrincipalType.USER, principal.getName(), principal.getType());
  }

  private String getRequestingUser() throws IllegalArgumentException {
    Principal principal = context.getPrincipal();
    LOG.trace("Got requesting principal {}", principal);
    return principal.getName();
  }
}
