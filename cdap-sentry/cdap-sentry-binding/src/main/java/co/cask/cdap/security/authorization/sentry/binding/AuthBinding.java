/*
 * Copyright 2016 Cask Data, Inc.
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

import co.cask.cdap.proto.element.EntityType;
import co.cask.cdap.proto.id.ApplicationId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.NamespacedArtifactId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf.AuthzConfVars;
import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import co.cask.cdap.security.authorization.sentry.model.Application;
import co.cask.cdap.security.authorization.sentry.model.Artifact;
import co.cask.cdap.security.authorization.sentry.model.Dataset;
import co.cask.cdap.security.authorization.sentry.model.Instance;
import co.cask.cdap.security.authorization.sentry.model.Namespace;
import co.cask.cdap.security.authorization.sentry.model.Program;
import co.cask.cdap.security.authorization.sentry.model.Stream;
import co.cask.cdap.security.authorization.sentry.policy.PrivilegeValidator;
import co.cask.cdap.security.spi.authentication.SecurityRequestContext;
import co.cask.cdap.security.spi.authorization.InvalidPrincipalTypeException;
import co.cask.cdap.security.spi.authorization.RoleAlreadyExistsException;
import co.cask.cdap.security.spi.authorization.RoleNotFoundException;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.core.common.ActiveRoleSet;
import org.apache.sentry.core.common.Authorizable;
import org.apache.sentry.core.common.Subject;
import org.apache.sentry.policy.common.PolicyEngine;
import org.apache.sentry.provider.common.AuthorizationProvider;
import org.apache.sentry.provider.common.ProviderBackend;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClient;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClientFactory;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.annotation.Nullable;

/**
 * This class instantiate the {@link AuthorizationProvider} configured in {@link AuthConf} and is responsible for
 * performing different authorization operation on CDAP entities by mapping them to authorizables
 * {@link #convertEntityToAuthorizables(String, EntityId)}
 */
class AuthBinding {
  private static final Logger LOG = LoggerFactory.getLogger(AuthBinding.class);
  private static final String COMPONENT_NAME = "cdap";
  private final AuthConf authConf;
  private final AuthorizationProvider authProvider;
  private final String instanceName;
  private final ActionFactory actionFactory;
  private final Set<Principal> superUsers;

  public AuthBinding(String sentrySite, String superUsers, String instanceName) {
    this.authConf = initAuthzConf(sentrySite);
    this.instanceName = instanceName;
    this.authProvider = createAuthProvider();
    this.actionFactory = new ActionFactory();
    this.superUsers = getSuperUsers(superUsers);
  }

  /**
   * Grants the given {@link Set} of {@link Action} on the given {@link EntityId} to the given {@link Role}
   *
   * @param entityId on which the actions need to be granted
   * @param role to which the actions needs to granted
   * @param actions the actions which needs to be granted
   * @throws RoleNotFoundException if the given principal does not exists as a role
   */
  void grant(final EntityId entityId, final Role role, Set<Action> actions) throws RoleNotFoundException {
    if (!roleExists(role)) {
      throw new RoleNotFoundException(role);
    }
    final String requestingUser = getRequestingUser();
    LOG.info("Granting actions {} on entity {} for role {} on request of {}", actions, entityId, role, requestingUser);
    for (final Action action : actions) {
      execute(new Command<Void>() {
        @Override
        public Void run(SentryGenericServiceClient client) throws Exception {
          client.grantPrivilege(requestingUser, role.getName(), COMPONENT_NAME, toTSentryPrivilege(entityId, action));
          return null;
        }
      });
    }
  }

  /**
   * Revokes a {@link Role role's} authorization to perform a set of {@link Action actions} on
   * an {@link EntityId}.
   *
   * @param entityId the {@link EntityId} whose {@link Action actions} are to be revoked
   * @param role the {@link Role} from which the actions needs to be revoked
   * @param actions the set of {@link Action actions} to revoke
   * @throws RoleNotFoundException if the given principal does not exists as a role
   */
  void revoke(final EntityId entityId, final Role role, Set<Action> actions) throws RoleNotFoundException {
    if (!roleExists(role)) {
      throw new RoleNotFoundException(role);
    }
    final String requestingUser = getRequestingUser();
    LOG.info("Revoking actions {} on entity {} from role {} on request of {}", actions, entityId, role, requestingUser);
    for (final Action action : actions) {
      execute(new Command<Void>() {
        @Override
        public Void run(SentryGenericServiceClient client) throws Exception {
          client.dropPrivilege(requestingUser, role.getName(), toTSentryPrivilege(entityId, action));
          return null;
        }
      });
    }
  }

  /**
   * Revokes all {@link Principal principals'} authorization to perform any {@link Action} on the given
   * {@link EntityId}.
   *
   * @param entityId the {@link EntityId} on which all {@link Action actions} are to be revoked
   */
  void revoke(EntityId entityId) {
    Set<Role> allRoles = listAllRoles();
    final List<TSentryPrivilege> allPrivileges = getAllPrivileges(allRoles);
    final List<TAuthorizable> tAuthorizables = toTAuthorizable(entityId);
    final String requestingUser = getRequestingUser();
    LOG.info("Revoking all actions for all users from entity {} on request of {}", entityId, requestingUser);
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        for (TSentryPrivilege curPrivileges : allPrivileges) {
          if (tAuthorizables.equals(curPrivileges.getAuthorizables())) {
            // if the privilege is on same authorizables then drop it
            client.dropPrivilege(requestingUser, COMPONENT_NAME, curPrivileges);
          }
        }
        return null;
      }
    });
  }

  /**
   * Check if the given {@link Principal} is allowed to perform the given {@link Action} on the {@link EntityId}
   *
   * @param entityId {@link EntityId} of the entity on which the action is being performed
   * @param principal the {@link Principal} who needs to perform this action
   * @param action {@link Action} the action which needs to be checked
   * @return true if the given {@link Principal} can perform the given {@link Action} on the given {@link EntityId}
   * else false
   */
  boolean authorize(EntityId entityId, Principal principal, Action action) {
    if (superUsers.contains(principal)) {
      // superusers are allowed to perform any action on all entities so need to to authorize
      LOG.info("Authorizing superuser with principal {} for action {} on entity {}", principal,
               action, entityId);
      return true;
    }
    List<Authorizable> authorizables = convertEntityToAuthorizables(instanceName, entityId);
    Set<ActionFactory.Action> actions = Sets.newHashSet(actionFactory.getActionByName(action.name()));
    return authProvider.hasAccess(new Subject(principal.getName()), authorizables, actions, ActiveRoleSet.ALL);
  }

  /**
   * Creates the given role.
   *
   * @param role the role to be created
   * @throws RoleAlreadyExistsException if the given role already exists
   */
  void createRole(final Role role) throws RoleAlreadyExistsException {
    if (roleExists(role)) {
      throw new RoleAlreadyExistsException(role);
    }
    final String requestingUser = getRequestingUser();
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.createRole(requestingUser, role.getName(), COMPONENT_NAME);
        LOG.info("Created role {} on request of {}", role, requestingUser);
        return null;
      }
    });
  }

  /**
   * Drops the given role.
   *
   * @param role the role to dropped
   * @throws RoleNotFoundException if the role to be dropped does not exists
   */
  void dropRole(final Role role) throws RoleNotFoundException {
    if (!roleExists(role)) {
      throw new RoleNotFoundException(role);
    }
    final String requestingUser = getRequestingUser();
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.dropRole(requestingUser, role.getName(), COMPONENT_NAME);
        LOG.info("Dropped role {} on request of {}", role, requestingUser);
        return null;
      }
    });
  }

  /**
   * Lists roles for the given principal
   *
   * @param principal the principal for which roles need to be listed
   * @return {@link Set} of {@link Role} to which this principal belongs to
   */
  Set<Role> listRolesForGroup(Principal principal) throws InvalidPrincipalTypeException {
    return getRoles(principal);
  }

  /**
   * Lists all roles
   * @return {@link Set} of all {@link Role}
   */
  Set<Role> listAllRoles() {
    return getRoles(null);
  }

  /**
   * Add a role to group principal
   *
   * @param role the role which needs to be added to the group principal
   * @param principal the group principal to which the role needs to be added
   * @throws RoleNotFoundException if the role to be added does not exists
   */
  void addRoleToGroup(final Role role, final Principal principal) throws RoleNotFoundException {
    if (!roleExists(role)) {
      throw new RoleNotFoundException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.addRoleToGroups(getRequestingUser(), role.getName(), COMPONENT_NAME,
                               ImmutableSet.of(principal.getName()));
        return null;
      }
    });
  }

  /**
   * Removed a role from group principal
   *
   * @param role the role which needs to be removed to the group principal
   * @param principal the group principal to which the role needs to be removed
   * @throws RoleNotFoundException if the role to be removed does not exists
   */
  void removeRoleFromGroup(final Role role, final Principal principal) throws RoleNotFoundException {
    if (!roleExists(role)) {
      throw new RoleNotFoundException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.deleteRoleToGroups(getRequestingUser(), role.getName(), COMPONENT_NAME,
                                  ImmutableSet.of(principal.getName()));
        return null;
      }
    });
  }

  private Set<Role> getRoles(@Nullable final Principal principal) {
    Set<Role> roles = new HashSet<>();
    final String requestingUser = getRequestingUser();
    Set<TSentryRole> tSentryRoles = execute(new Command<Set<TSentryRole>>() {
      @Override
      public Set<TSentryRole> run(SentryGenericServiceClient client) throws Exception {
        return principal == null ? client.listAllRoles(requestingUser, COMPONENT_NAME) :
          client.listRolesByGroupName(requestingUser, principal.getName(), COMPONENT_NAME);
      }
    });
    for (TSentryRole tSentryRole : tSentryRoles) {
      roles.add(new Role(tSentryRole.getRoleName()));
    }
    if (principal == null) {
      LOG.info("Listed all roles {} on request of {}", roles, requestingUser);
    } else {
      LOG.info("Listed roles {} for principal {} on request of {}", roles, principal, requestingUser);
    }
    return ImmutableSet.copyOf(roles);
  }

  /**
   * Gets a {@link Set} of {@link Principal} of superusers which is provided throug
   * {@link AuthConf#SERVICE_SUPERUSERS}
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

  /**
   * Maps the given {@link EntityId} to {@link Authorizable}. To see a valid set of {@link Authorizable}
   * please see {@link PrivilegeValidator} which is responsible for validating these authorizables positions and action.
   *
   * @param instanceName the name of the cdap instance
   * @param entityId the {@link EntityId} which needs to be mapped to list of {@link Authorizable}
   * @return a {@link List} of {@link Authorizable} which represents the given {@link EntityId}
   */
  @VisibleForTesting
  static List<org.apache.sentry.core.common.Authorizable> convertEntityToAuthorizables(
    final String instanceName, final EntityId entityId) {
    List<org.apache.sentry.core.common.Authorizable> authorizables = new LinkedList<>();
    // cdap instance is not a concept in cdap entities. In sentry integration we need to grant privileges on the
    // instance so that users can create namespace inside the instance etc.
    authorizables.add(new Instance(instanceName));
    getAuthorizable(entityId, authorizables);
    return authorizables;
  }

  private AuthConf initAuthzConf(String sentrySite) {
    if (Strings.isNullOrEmpty(sentrySite)) {
      throw new IllegalArgumentException(String.format("The value for %s is null or empty. Please configure it to " +
                                                         "the absolute path of sentry-site.xml in cdap-site.xml",
                                                       AuthConf.SENTRY_SITE_URL));
    }
    AuthConf authConf;
    try {
      authConf = sentrySite.startsWith("file://") ? new AuthConf(new URL(sentrySite)) :
        new AuthConf(new URL("file://" + sentrySite));
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(String.format("The path provided for sentry-site.xml in property %s is " +
                                                         "invalid. Please configure it to the absolute path of " +
                                                         "sentry-site.xml in cdap-site.xml",
                                                       AuthConf.SENTRY_SITE_URL), e);
    }
    return authConf;
  }

  /**
   * Instantiate the configured {@link AuthorizationProvider}
   *
   * @return {@link AuthorizationProvider} configured in {@link AuthConf}
   */
  private AuthorizationProvider createAuthProvider() {

    String authProviderName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER.getVar(),
                                           AuthzConfVars.AUTHZ_PROVIDER.getDefault());

    String providerBackendName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getVar(),
                                              AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getDefault());

    String policyEngineName = authConf.get(AuthzConfVars.AUTHZ_POLICY_ENGINE.getVar(),
                                           AuthzConfVars.AUTHZ_POLICY_ENGINE.getDefault());

    String resourceName = authConf.get(AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getVar(),
                                       AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getDefault());

    LOG.debug("Trying to instantiate authorization provider {}, with provider backend {}, policy engine {} and " +
                "resource {}",
              authProviderName, providerBackendName, policyEngineName, resourceName);

    // Instantiate the configured providerBackend
    try {
      // get the current context classloader
      ClassLoader classLoader = Thread.currentThread().getContextClassLoader();

      if (resourceName != null && resourceName.startsWith("classpath:")) {
        String resourceFileName = resourceName.substring("classpath:".length());
        URL resource = classLoader.getResource(resourceFileName);
        Preconditions.checkState(resource != null, "Resource %s could not be loaded from authorizer classloader",
                                 resourceFileName);
        resourceName = resource.getPath();
      }

      // instantiate the configured provider backend
      Constructor<?> providerBackendConstructor = classLoader.loadClass(providerBackendName)
        .getDeclaredConstructor(Configuration.class, String.class);
      providerBackendConstructor.setAccessible(true);
      ProviderBackend providerBackend = (ProviderBackend) providerBackendConstructor.newInstance(authConf,
                                                                                                 resourceName);
      if (providerBackend instanceof SentryGenericProviderBackend) {
        ((SentryGenericProviderBackend) providerBackend).setComponentType(COMPONENT_NAME);
        ((SentryGenericProviderBackend) providerBackend).setServiceName(instanceName);
      }

      // instantiate the configured policy engine
      Constructor<?> policyConstructor = classLoader.loadClass(policyEngineName)
        .getDeclaredConstructor(ProviderBackend.class);
      policyConstructor.setAccessible(true);
      PolicyEngine policyEngine = (PolicyEngine) policyConstructor.newInstance(providerBackend);

      // Instantiate the configured authz provider
      Constructor<?> authzProviderConstructor = classLoader.loadClass(authProviderName).getDeclaredConstructor(
        Configuration.class, String.class, PolicyEngine.class);
      authzProviderConstructor.setAccessible(true);
      return (AuthorizationProvider) authzProviderConstructor.newInstance(authConf, resourceName, policyEngine);
    } catch (Exception e) {
      throw Throwables.propagate(e);
    }
  }

  private List<TSentryPrivilege> getAllPrivileges(final Set<Role> roles) {
    return execute(new Command<List<TSentryPrivilege>>() {
      @Override
      public List<TSentryPrivilege> run(SentryGenericServiceClient client) throws Exception {
        final List<TSentryPrivilege> tSentryPrivileges = new ArrayList<>();
        for (Role role : roles) {
          tSentryPrivileges.addAll(client.listPrivilegesByRoleName(getRequestingUser(), role.getName(),
                                                                   COMPONENT_NAME, instanceName));
        }
        return ImmutableList.copyOf(tSentryPrivileges);
      }
    });
  }

  private boolean roleExists(Role role) {
    return listAllRoles().contains(role);
  }

  private TSentryPrivilege toTSentryPrivilege(EntityId entityId, Action action) {
    List<Authorizable> authorizables = convertEntityToAuthorizables(instanceName, entityId);
    List<TAuthorizable> tAuthorizables = new ArrayList<>();
    for (Authorizable authorizable : authorizables) {
      tAuthorizables.add(new TAuthorizable(authorizable.getTypeName(), authorizable.getName()));
    }
    return new TSentryPrivilege(COMPONENT_NAME, instanceName, tAuthorizables, action.name());
  }

  private List<TAuthorizable> toTAuthorizable(EntityId entityId) {
    return toTSentryPrivilege(entityId, Action.ALL).getAuthorizables();
  }

  private <T> T execute(Command<T> cmd) {
    try {
      SentryGenericServiceClient client = getClient();
      try {
        return cmd.run(client);
      } finally {
        client.close();
      }
    } catch (Exception e) {
      throw Throwables.propagate(e);
    }
  }

  /**
   * A Command is a closure used to pass a block of code from individual functions to execute, which centralizes
   * connection error handling. Command is parameterized on the return type of the function.
   */
  private interface Command<T> {
    T run(SentryGenericServiceClient client) throws Exception;
  }

  private SentryGenericServiceClient getClient() throws Exception {
    return SentryGenericServiceClientFactory.create(authConf);
  }

  /**
   * Maps {@link EntityId} to a {@link List} of {@link co.cask.cdap.security.authorization.sentry.model.Authorizable}
   * by recursively working its way from a given entity.
   *
   * @param entityId {@link EntityId} the entity which needs to be mapped to a list of authorizables
   * @param authorizables {@link List} of {@link co.cask.cdap.security.authorization.sentry.model.Authorizable} to
   * add authorizables to
   */
  private static void getAuthorizable(EntityId entityId,
                                      List<org.apache.sentry.core.common.Authorizable> authorizables) {
    EntityType entityType = entityId.getEntity();
    switch (entityType) {
      case NAMESPACE:
        authorizables.add(new Namespace(((NamespaceId) entityId).getNamespace()));
        break;
      case ARTIFACT:
        NamespacedArtifactId artifactId = (NamespacedArtifactId) entityId;
        getAuthorizable(artifactId.getParent(), authorizables);
        authorizables.add(new Artifact((artifactId).getArtifact()));
        break;
      case APPLICATION:
        ApplicationId applicationId = (ApplicationId) entityId;
        getAuthorizable(applicationId.getParent(), authorizables);
        authorizables.add(new Application((applicationId).getApplication()));
        break;
      case DATASET:
        DatasetId dataset = (DatasetId) entityId;
        getAuthorizable(dataset.getParent(), authorizables);
        authorizables.add(new Dataset((dataset).getDataset()));
        break;
      case STREAM:
        StreamId streamId = (StreamId) entityId;
        getAuthorizable(streamId.getParent(), authorizables);
        authorizables.add(new Stream((streamId).getStream()));
        break;
      case PROGRAM:
        ProgramId programId = (ProgramId) entityId;
        getAuthorizable(programId.getParent(), authorizables);
        authorizables.add(new Program(programId.getProgram()));
        break;
      default:
        throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
    }
  }

  private String getRequestingUser() throws IllegalArgumentException {
    // Preconditions.checkArgument(!SecurityRequestContext.getUserId().isPresent(), "No authenticated user found.");
    // TODO Issues-15: To support testing on insecure clusters where we don't have security in cdap we will returning a
    // dummy username. Once the development is almost finalized we should remove the below dummy username and
    // uncomment the line above.
    if (SecurityRequestContext.getUserId() == null) {
      return "cdap";
    }
    return SecurityRequestContext.getUserId();
  }
}
