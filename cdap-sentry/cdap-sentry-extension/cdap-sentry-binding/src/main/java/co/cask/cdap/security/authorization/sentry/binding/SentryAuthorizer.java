/*
 * Copyright © 2016-2017 Cask Data, Inc.
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

package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AlreadyExistsException;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.Authorizer;
import co.cask.cdap.security.spi.authorization.NotFoundException;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Strings;
import com.google.common.collect.Collections2;
import com.google.common.collect.Sets;
import org.apache.sentry.core.common.Authorizable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
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
  private static final String ENTITY_ROLE_PREFIX = ".";

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
  public void grant(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    LOG.trace("Granting {} on {} to {}", actions, entityId, principal);
    switch (principal.getType()) {
      case ROLE:
        binding.grant(entityId, new Role(principal.getName()), actions, getRequestingUser());
        break;
      case USER:
        // get the group for the user to perform group based grant
        performGroupBasedGrant(entityId, getGroupPrincipal(principal), actions);
        break;
      case GROUP:
        performGroupBasedGrant(entityId, principal, actions);
        break;
      default:
        throw new IllegalArgumentException(
          String.format("The given principal '%s' is of unsupported type '%s'.", principal.getName(),
                        principal.getType()));
    }
    invalidateCache();
    LOG.trace("Granted {} on {} to {}", actions, entityId, principal);
  }

  @Override
  public void revoke(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    LOG.trace("Revoking {} on {} to {}", actions, entityId, principal);
    Role entityRole;
    switch (principal.getType()) {
      case ROLE:
        binding.revoke(entityId, new Role(principal.getName()), actions, getRequestingUser());
        break;
      case USER:
        // get the group for the user and the role associated with entity and perform revoke
        entityRole = getEntityUserRole(entityId, getGroupPrincipal(principal));
        binding.revoke(entityId, entityRole, actions);
        // true because if there are other privileges associated with this role then we don't want to cleanup the role
        // at this point
        cleanUpEntityRole(entityRole, true);
        break;
      case GROUP:
        // get the role associated with the entity for the group and perform revoke
        entityRole = getEntityUserRole(entityId, principal);
        binding.revoke(entityId, entityRole, actions);
        // true because if there are other privileges associated with this role then we don't want to cleanup the role
        // at this point
        cleanUpEntityRole(entityRole, true);
        break;
      default:
        throw new IllegalArgumentException(
          String.format("The given principal '%s' is of unsupported type '%s'.", principal.getName(),
                        principal.getType()));
    }
    invalidateCache();
    LOG.trace("Revoked {} on {} to {}", actions, entityId, principal);
  }

  /**
   * Invalidate all entries in the cache. This method should be called to invalidate cache on grant/revoke or any
   * such actions which modifies the privileges. For details see CDAP-11929
   */
  private void invalidateCache() {
    LOG.debug("Invalidating all entries in cache...");
    // TODO: remove this method when grant/revoke code gets removed
  }

  @Override
  public void revoke(EntityId entityId) throws Exception {
    LOG.debug("Revoking all privileges on {}", entityId);
    binding.revoke(entityId);
    // remove the roles created for this entity
    for (Role entityRole : getEntityRoles(entityId)) {
      // false as we don't want to check if there are privileges associated with the entity role or not
      // since the entity itself is deleted we want to delete all roles associated with it
      cleanUpEntityRole(entityRole, false);
    }
    invalidateCache();
    LOG.debug("Revoked all privileges on {}", entityId);
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
    Preconditions.checkArgument(
      Principal.PrincipalType.USER == principal.getType(),
      "Only support principal type %s for authorization, given principal %s is of type %s",
      Principal.PrincipalType.USER, principal.getName(), principal.getType());

    Set<WildcardPolicy> policies = binding.getPolicies(principal);
    LOG.debug("Got policies {} for principal {}, entity {} and actions {}", policies, principal, entityId, actions);
    if (policies.isEmpty()) {
      throw new UnauthorizedException(principal, actions, entityId);
    }

    List<Authorizable> authorizables = new ArrayList<>();
    binding.toAuthorizables(entityId, authorizables);

    Set<ActionFactory.Action> checkActions = binding.toSentryActions(actions);

    // Check each action against each policy
    Set<ActionFactory.Action> allowedActions = new HashSet<>(actions.size());
    for (ActionFactory.Action sentryAction : checkActions) {
      for (WildcardPolicy policy : policies) {
        if (policy.isAllowed(authorizables, sentryAction)) {
          allowedActions.add(sentryAction);
          // no need to check the other policies since this action is allowed by this policy
          break;
        }
      }
    }

    if (!checkActions.equals(allowedActions)) {
      throw new UnauthorizedException(principal, actions, entityId);
    }
  }

  @Override
  public co.cask.cdap.api.Predicate<EntityId> createFilter(final Principal principal) throws Exception {
    Preconditions.checkArgument(
      Principal.PrincipalType.USER == principal.getType(),
      "Only support principal type %s for authorization, given principal %s is of type %s",
      Principal.PrincipalType.USER, principal.getName(), principal.getType());

    final Set<WildcardPolicy> policies = binding.getPolicies(principal);
    LOG.debug("Got policies {} for principal {}", policies, principal);

    return new co.cask.cdap.api.Predicate<EntityId>() {
      @Override
      public boolean apply(EntityId entityId) {
        if (policies.isEmpty()) {
          return false;
        }

        List<Authorizable> authorizables = new ArrayList<>();
        binding.toAuthorizables(entityId, authorizables);

        // Even if one policy makes the entity visible, then return true
        for (WildcardPolicy policy : policies) {
          if (policy.isVisible(authorizables)) {
            return true;
          }
        }
        return false;
      }
    };
  }

  private synchronized void performGroupBasedGrant(EntityId entityId, Principal principal,
                                                   Set<Action> actions) throws Exception {
    Role dotRole = getEntityUserRole(entityId, principal);
    try {
      binding.createRole(dotRole);
      LOG.debug("Created role {}", dotRole);
    } catch (AlreadyExistsException e) {
      LOG.debug("Dot role {} already exists.", dotRole);
    }
    try {
      binding.addRoleToGroup(dotRole, principal);
      LOG.debug("Added role {} to group {}", dotRole, principal);
      binding.grant(entityId, dotRole, actions);
      LOG.debug("Granted actions {} to role {} on entity {}", actions, dotRole, entityId);
    } catch (NotFoundException e) {
      // Not possible, since we just made sure it exists, and this method is synchronized
      LOG.debug("Role {} not found. This is unexpected since its existence was just ensured.", dotRole);
    }
  }

  /**
   * Drops a role if it was created by cdap i.e. it starts with ENTITY_ROLE_PREFIX and there is no privileges
   * associated with it
   * @param entityRole the role which needs to be dropped if empty
   * @param checkPrivilege whether to check if the role has privileges associated with it before
   * deleting or not. If set to true then the role will not be deleted if there are privileges associated with the role
   */
  private void cleanUpEntityRole(Role entityRole, boolean checkPrivilege) throws Exception {
    // this should not be called for any other role except entity roles i.e. the ones which start with
    // ENTITY_ROLE_PREFIX
    if (!entityRole.getName().startsWith(ENTITY_ROLE_PREFIX)) {
      throw new IllegalArgumentException(String.format("The given role %s is not an entity role. " +
                                                         "Please use drop role to remove this role.", entityRole));
    }
    // if check privilege was set to true and there are privileges associated with this role then
    // don't clean it up
    if (checkPrivilege && !listPrivileges(entityRole).isEmpty()) {
      LOG.debug("Skipping role cleanup for role {}", entityRole);
      return;
    }
    try {
      binding.dropRole(entityRole);
      LOG.debug("Successfully dropped role {}", entityRole);
    } catch (NotFoundException e) {
      // This is a dot role. It should be ok for deletion to fail. This happens because while creating a new entity,
      // we first revoke any orphaned privileges on the entity. During that operation this role may not exist.
      LOG.debug("Trying to delete role {}, but it was not found. Ignoring since it's an entity role.", entityRole);
    }
  }

  /**
   * Gets all the entity roles associated with the given {@link EntityId}
   * @param entityId the entity for which roles need to be obtained
   * @return {@link Set} of {@link Role} for the given entity
   */
  private Set<Role> getEntityRoles(final EntityId entityId) throws Exception {
    final String curEntityRolePrefix = Joiner.on(ENTITY_ROLE_PREFIX).join("", entityId.toString());

    Predicate<Role> filter = new Predicate<Role>() {
      public boolean apply(Role role) {
        return role.getName().startsWith(curEntityRolePrefix);
      }
    };

    // get all roles and filter roles which belongs to this this entity
    Set<Role> allRoles = listAllRoles();
    return Sets.newHashSet(Collections2.filter(allRoles, filter));
  }

  /**
   * Returns the groups for a user. We just take the user's name and return that as the group for the user as our
   * current assumption is that every user will have their own group to which only they will belong and the group name
   * will be same as the user name. Note: This assumption will not be true in all scenarios See CDAP-9125 for details.
   *
   * @param principal the user's principal
   * @return {@link Principal} of type {@link Principal.PrincipalType#GROUP} where the name is same as user name
   */
  private Principal getGroupPrincipal(Principal principal) {
    return new Principal(principal.getName(), Principal.PrincipalType.GROUP);
  }

  private Role getEntityUserRole(EntityId entityId, Principal principal) {
    return new Role(
      Joiner.on(ENTITY_ROLE_PREFIX).join(
        "", entityId.toString(), principal.getType().name().toLowerCase().charAt(0), principal.getName()
      )
    );
  }

  private String getRequestingUser() throws IllegalArgumentException {
    Principal principal = context.getPrincipal();
    LOG.trace("Got requesting principal {}", principal);
    return principal.getName();
  }
}
