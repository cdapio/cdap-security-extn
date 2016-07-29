/*
 * Copyright © 2016 Cask Data, Inc.
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

import co.cask.cdap.api.Predicate;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.Authorizer;
import co.cask.cdap.security.spi.authorization.RoleAlreadyExistsException;
import co.cask.cdap.security.spi.authorization.RoleNotFoundException;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashSet;
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
  private Set<Principal> superUsers;
  private AuthorizationContext context;

  @Override
  public void initialize(AuthorizationContext context) throws Exception {
    Properties properties = context.getExtensionProperties();
    String sentrySiteUrl = properties.getProperty(AuthConf.SENTRY_SITE_URL);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(AuthConf.SENTRY_SITE_URL),
                                "Path to sentry-site.xml path is not specified in cdap-site.xml. Please provide the " +
                                  "path to sentry-site.xml in cdap-site.xml with property name %s",
                                AuthConf.SENTRY_SITE_URL);
    String superUsers = properties.getProperty(AuthConf.SUPERUSERS);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(superUsers),
                                "No superusers defined in cdap-site.xml. Please provide a comma separated list of " +
                                  "users who will be superusers with property name %s. Example: user1,user2",
                                AuthConf.SUPERUSERS);

    String sentryAdminGroup = properties.getProperty(AuthConf.SENTRY_ADMIN_GROUP);
    if (Strings.isNullOrEmpty(sentryAdminGroup)) {
      LOG.warn("No Sentry admin group defined in cdap-site.xml. This group will be used to grant access to users " +
                 "after they have successfully created entities in CDAP. To use this feature and fix this warning, " +
                 "please set {} in cdap-site.xml to a single admin group defined in the sentry service as the " +
                 "property sentry.service.admin.group.", AuthConf.SENTRY_ADMIN_GROUP);
    }
    Preconditions.checkArgument(!sentryAdminGroup.contains(","),
                                "Please provide exactly one Sentry admin group at %s in cdap-site.xml. Found '%s'.",
                                AuthConf.SENTRY_ADMIN_GROUP, sentryAdminGroup);
    String instanceName = properties.containsKey(AuthConf.INSTANCE_NAME) ?
      properties.getProperty(AuthConf.INSTANCE_NAME) :
      AuthConf.AuthzConfVars.getDefault(AuthConf.INSTANCE_NAME);

    LOG.info("Configuring SentryAuthorizer with sentry-site.xml at {} and cdap instance name {}",
               sentrySiteUrl, instanceName);
    this.superUsers = getSuperUsers(superUsers);
    this.binding = new AuthBinding(sentrySiteUrl, instanceName, sentryAdminGroup);
    this.context = context;
  }

  @Override
  public void grant(EntityId entityId, Principal principal, Set<Action> actions) throws RoleNotFoundException {
    switch (principal.getType()) {
      case ROLE:
        binding.grant(entityId, new Role(principal.getName()), actions, getRequestingUser());
        break;
      case USER:
        performUserBasedGrant(entityId, principal, actions);
        break;
      default:
        throw new IllegalArgumentException(
          String.format("The given principal '%s' is of type '%s'. In Sentry grants can only be done on " +
                          "roles. Please add the '%s':'%s' to a role and perform grant on the role.",
                        principal.getName(), principal.getType(), principal.getType(), principal.getName()));
    }
  }

  @Override
  public void revoke(EntityId entityId, Principal principal, Set<Action> actions) throws RoleNotFoundException {
    Preconditions.checkArgument(principal.getType() == Principal.PrincipalType.ROLE, "The given principal '%s' is of " +
                                  "type '%s'. In Sentry revoke can only be done on roles.",
                                principal.getName(), principal.getType());
    binding.revoke(entityId, new Role(principal.getName()), actions, getRequestingUser());
  }

  @Override
  public void revoke(EntityId entityId) {
    binding.revoke(entityId);
    // remove the role created for this entity
    Role role = new Role(ENTITY_ROLE_PREFIX + entityId.toString());
    try {
      binding.dropRole(role);
    } catch (RoleNotFoundException e) {
      // This is a dot role. It should be ok for deletion to fail. This happens because while creating a new entity,
      // we first revoke any orphaned privileges on the entity. During that operation this role may not exist.
      LOG.debug("Trying to delete role {}, but it was not found. Ignoring.", role);
    }
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) {
    return binding.listPrivileges(principal, getRequestingUser());
  }

  @Override
  public void createRole(Role role) throws RoleAlreadyExistsException {
    binding.createRole(role, getRequestingUser());
  }

  @Override
  public void dropRole(Role role) throws RoleNotFoundException {
    binding.dropRole(role, getRequestingUser());
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws RoleNotFoundException {
    binding.addRoleToGroup(role, principal, getRequestingUser());
  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws RoleNotFoundException {
    binding.removeRoleFromGroup(role, principal, getRequestingUser());
  }

  @Override
  public Set<Role> listRoles(Principal principal) {
    Preconditions.checkArgument(principal.getType() != Principal.PrincipalType.ROLE, "The given principal '%s' is of " +
                                "type '%s'. In Sentry revoke roles can only be listed for '%s' and '%s'",
                                principal.getName(), principal.getType(), Principal.PrincipalType.USER,
                                Principal.PrincipalType.GROUP);
    return binding.listRolesForGroup(principal, getRequestingUser());
  }

  @Override
  public Set<Role> listAllRoles() {
    return binding.listAllRoles(getRequestingUser());
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    Preconditions.checkArgument(Principal.PrincipalType.USER == principal.getType(), "The given principal '%s' is of " +
                                "type '%s'. In Sentry authorization checks can only be performed on principal type " +
                                "'%s'.", principal.getName(), principal.getType(), Principal.PrincipalType.USER);
    if (superUsers.contains(principal)) {
      // superusers are allowed to perform any action on all entities so need to authorize
      LOG.debug("Authorizing superuser with principal {} for actions {} on entity {}", principal, actions, entityId);
      return;
    }

    if (!binding.authorize(entityId, principal, actions)) {
      throw new UnauthorizedException(principal, actions, entityId);
    }
  }

  @Override
  public Predicate<EntityId> createFilter(Principal principal) throws Exception {
    if (superUsers.contains(principal)) {
      // superusers are allowed to perform any action on all entities so need to filter
      LOG.debug("No filtering necessary for superuser {}. Returning an allow-all filter.", principal);
      return ALLOW_ALL;
    }
    return super.createFilter(principal);
  }

  private synchronized void performUserBasedGrant(EntityId entityId, Principal principal, Set<Action> actions) {
    // make sure that the request is part of a larger request for creating an entity
    if (!Collections.singleton(Action.ALL).equals(actions)) {
      throw new IllegalArgumentException("Grants for users are only supported in Sentry as part of a create " +
                                           "operation.");
    }
    Role dotRole = new Role(ENTITY_ROLE_PREFIX + entityId.toString());
    try {
      binding.createRole(dotRole);
      LOG.debug("Created role {}", dotRole);
    } catch (RoleAlreadyExistsException e) {
      LOG.debug("Dot role {} already exists.", dotRole);
    }
    try {
      binding.addRoleToGroup(dotRole, new Principal(principal.getName(), Principal.PrincipalType.GROUP));
      LOG.debug("Added role {} to group {}", dotRole, principal);
      binding.grant(entityId, dotRole, actions);
      LOG.debug("Granted actions {} to role {} on entity {}", actions, dotRole, entityId);
    } catch (RoleNotFoundException e) {
      // Not possible, since we just made sure it exists, and this method is synchronized
      LOG.debug("Role {} not found. This is unexpected since its existence was just ensured.", dotRole);
    }
  }

  /**
   * Gets a {@link Set} of {@link Principal} of superusers which is provided through
   * {@link AuthConf#SUPERUSERS}
   *
   * @return {@link Set} of {@link Principal} of superusers
   */
  private Set<Principal> getSuperUsers(String superUsers) {
    Set<Principal> result = new HashSet<>();
    for (String curUser : Splitter.on(",").trimResults().split(superUsers)) {
      result.add(new Principal(curUser, Principal.PrincipalType.USER));
    }
    return result;
  }

  private String getRequestingUser() throws IllegalArgumentException {
    Principal principal = context.getPrincipal();
    LOG.trace("Got requesting principal {}", principal);
    return principal.getName();
  }
}
