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
import co.cask.cdap.proto.id.ArtifactId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.InstanceId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf.AuthzConfVars;
import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import co.cask.cdap.security.authorization.sentry.model.Application;
import co.cask.cdap.security.authorization.sentry.model.Artifact;
import co.cask.cdap.security.authorization.sentry.model.Authorizable;
import co.cask.cdap.security.authorization.sentry.model.Dataset;
import co.cask.cdap.security.authorization.sentry.model.Instance;
import co.cask.cdap.security.authorization.sentry.model.Namespace;
import co.cask.cdap.security.authorization.sentry.model.Program;
import co.cask.cdap.security.authorization.sentry.model.Stream;
import co.cask.cdap.security.authorization.sentry.policy.ModelAuthorizables;
import co.cask.cdap.security.authorization.sentry.policy.PrivilegeValidator;
import co.cask.cdap.security.spi.authorization.RoleAlreadyExistsException;
import co.cask.cdap.security.spi.authorization.RoleNotFoundException;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.core.common.ActiveRoleSet;
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
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.annotation.Nullable;

/**
 * This class instantiate the {@link AuthorizationProvider} configured in {@link AuthConf} and is responsible for
 * performing different authorization operation on CDAP entities by mapping them to authorizables
 * {@link #toSentryAuthorizables(EntityId)}
 */
class AuthBinding {
  private static final Logger LOG = LoggerFactory.getLogger(AuthBinding.class);
  private static final String COMPONENT_NAME = "cdap";
  private final AuthConf authConf;
  private final AuthorizationProvider authProvider;
  private final String instanceName;
  private final ActionFactory actionFactory;

  AuthBinding(String sentrySite, String instanceName) {
    this.authConf = initAuthzConf(sentrySite);
    this.instanceName = instanceName;
    this.authProvider = createAuthProvider();
    this.actionFactory = new ActionFactory();
  }

  /**
   * Grants the given {@link Set} of {@link Action} on the given {@link EntityId} to the given {@link Role}
   *
   * @param entityId on which the actions need to be granted
   * @param role to which the actions needs to granted
   * @param actions the actions which needs to be granted
   * @param requestingUser the user executing this operation
   * @throws RoleNotFoundException if the given role does not exist
   */
  void grant(final EntityId entityId, final Role role, Set<Action> actions,
             final String requestingUser) throws RoleNotFoundException {
    if (!roleExists(role, requestingUser)) {
      throw new RoleNotFoundException(role);
    }
    LOG.debug("Granting actions {} on entity {} for role {}; Requesting user: {}",
              actions, entityId, role, requestingUser);
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
   * @param requestingUser the user executing this operation
   * @throws RoleNotFoundException if the given role does not exist
   */
  void revoke(final EntityId entityId, final Role role, Set<Action> actions,
              final String requestingUser) throws RoleNotFoundException {
    if (!roleExists(role, requestingUser)) {
      throw new RoleNotFoundException(role);
    }
    LOG.debug("Revoking actions {} on entity {} from role {}; Requesting user: {}",
              actions, entityId, role, requestingUser);
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
   * @param requestingUser the user executing this operation
   */
  void revoke(EntityId entityId, final String requestingUser) {
    Set<Role> allRoles = listAllRoles(requestingUser);
    final List<TSentryPrivilege> allPrivileges = getAllPrivileges(allRoles, requestingUser);
    final List<TAuthorizable> tAuthorizables = toTAuthorizable(entityId);
    LOG.debug("Revoking all actions for all users from entity {}; Requesting user: {}", entityId, requestingUser);
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
   * @param actions {@link Action actions} that need to be checked for authorization
   * @return true if the given {@link Principal} can perform the given {@link Action} on the given {@link EntityId}
   * else false
   */
  boolean authorize(EntityId entityId, Principal principal, Set<Action> actions) {
    List<org.apache.sentry.core.common.Authorizable> authorizables = toSentryAuthorizables(entityId);
    Set<ActionFactory.Action> sentryActions = Sets.newHashSet(
      Collections2.transform(actions, new Function<Action, ActionFactory.Action>() {
        @Override
        public ActionFactory.Action apply(Action action) {
          return actionFactory.getActionByName(action.name());
        }
      }));
    return authProvider.hasAccess(new Subject(principal.getName()), authorizables, sentryActions, ActiveRoleSet.ALL);
  }

  /**
   * Lists {@link Privilege privileges} for the given {@link Principal}
   *
   * @param principal the principal for which the privileges has to be listed
   * @param requestingUser the user executing this operation
   * @return {@link Set} of {@link Privilege privilege} for the given principal
   */
  Set<Privilege> listPrivileges(Principal principal, String requestingUser) {
    Set<Role> roles = getRoles(principal, requestingUser);
    LOG.debug("Listing all privileges for {}; Requesting user: {}", principal, requestingUser);
    List<TSentryPrivilege> allPrivileges = getAllPrivileges(roles, requestingUser);
    return toPrivileges(allPrivileges);
  }

  @VisibleForTesting
  Set<Privilege> toPrivileges(List<TSentryPrivilege> allPrivileges) {
    Set<Privilege> privileges = new HashSet<>();
    for (TSentryPrivilege sentryPrivilege : allPrivileges) {
      List<TAuthorizable> authorizables = sentryPrivilege.getAuthorizables();
      if (authorizables.isEmpty()) {
        continue;
      }
      EntityId parent = null;
      for (TAuthorizable authorizable : authorizables) {
        parent = toEntityId(authorizable, parent);
      }
      privileges.add(new Privilege(parent, Action.valueOf(sentryPrivilege.getAction().toUpperCase())));
    }
    return privileges;
  }

  /**
   * Creates the given role.
   *
   * @param role the role to be created
   * @param requestingUser the user executing this operation
   * @throws RoleAlreadyExistsException if the given role already exists
   */
  void createRole(final Role role, final String requestingUser) throws RoleAlreadyExistsException {
    if (roleExists(role, requestingUser)) {
      throw new RoleAlreadyExistsException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.createRole(requestingUser, role.getName(), COMPONENT_NAME);
        LOG.debug("Created role {}; Requesting user: {}", role, requestingUser);
        return null;
      }
    });
  }

  /**
   * Drops the given role.
   *
   * @param role the role to dropped
   * @param requestingUser the user executing this operation
   * @throws RoleNotFoundException if the role to be dropped does not exists
   */
  void dropRole(final Role role, final String requestingUser) throws RoleNotFoundException {
    if (!roleExists(role, requestingUser)) {
      throw new RoleNotFoundException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.dropRole(requestingUser, role.getName(), COMPONENT_NAME);
        LOG.info("Dropped role {}; Requesting user: {}", role, requestingUser);
        return null;
      }
    });
  }

  /**
   * Lists roles for the given principal
   *
   * @param principal the principal for which roles need to be listed
   * @param requestingUser the user executing this operation
   * @return {@link Set} of {@link Role} to which this principal belongs to
   */
  Set<Role> listRolesForGroup(Principal principal, final String requestingUser) {
    return getRoles(principal, requestingUser);
  }

  /**
   * Lists all roles
   *
   * @param requestingUser the user executing this operation
   * @return {@link Set} of all {@link Role}
   */
  Set<Role> listAllRoles(final String requestingUser) {
    return getRoles(null, requestingUser);
  }

  /**
   * Add a role to group principal
   *
   * @param role the role which needs to be added to the group principal
   * @param principal the group principal to which the role needs to be added
   * @param requestingUser the user executing this operation
   * @throws RoleNotFoundException if the role to be added does not exists
   */
  void addRoleToGroup(final Role role, final Principal principal,
                      final String requestingUser) throws RoleNotFoundException {
    if (!roleExists(role, requestingUser)) {
      throw new RoleNotFoundException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.addRoleToGroups(requestingUser, role.getName(), COMPONENT_NAME,
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
   * @param requestingUser the user executing this operation
   * @throws RoleNotFoundException if the role to be removed does not exists
   */
  void removeRoleFromGroup(final Role role, final Principal principal,
                           final String requestingUser) throws RoleNotFoundException {
    if (!roleExists(role, requestingUser)) {
      throw new RoleNotFoundException(role);
    }
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.deleteRoleToGroups(requestingUser, role.getName(), COMPONENT_NAME,
                                  ImmutableSet.of(principal.getName()));
        return null;
      }
    });
  }

  /**
   * Maps the given {@link EntityId} to {@link Authorizable}. To see a valid set of {@link Authorizable}
   * please see {@link PrivilegeValidator} which is responsible for validating these authorizables positions and action.
   *
   * @param entityId the {@link EntityId} which needs to be mapped to list of {@link Authorizable}
   * @return a {@link List} of {@link Authorizable} which represents the given {@link EntityId}
   */
  @VisibleForTesting
  List<org.apache.sentry.core.common.Authorizable> toSentryAuthorizables(final EntityId entityId) {
    List<org.apache.sentry.core.common.Authorizable> authorizables = new LinkedList<>();
    toAuthorizables(entityId, authorizables);
    return authorizables;
  }

  private Set<Role> getRoles(@Nullable final Principal principal, final String requestingUser) {
    // if the specified principal is non-null and is a role, then we just return a singleton set containing that role
    if (principal != null && Principal.PrincipalType.ROLE == principal.getType()) {
      return Collections.singleton(new Role(principal.getName()));
    }
    Set<Role> roles = new HashSet<>();
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
      LOG.debug("Listed all roles {}; Requesting user: {}", roles, requestingUser);
    } else {
      LOG.debug("Listed roles {} for principal {}; Requesting user: {}", roles, principal, requestingUser);
    }
    return ImmutableSet.copyOf(roles);
  }

  /**
   * Checks if the given role exists
   * @param role the role to be checked for existence
   * @param requestingUser the user executing this operation
   * @return true if the role exists else false
   */
  boolean roleExists(Role role, final String requestingUser) {
    return listAllRoles(requestingUser).contains(role);
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
      Class<?> providerBackendClass = classLoader.loadClass(providerBackendName);
      Constructor<?> providerBackendConstructor = providerBackendClass.getDeclaredConstructor(Configuration.class,
                                                                                              String.class);
      providerBackendConstructor.setAccessible(true);
      ProviderBackend providerBackend = (ProviderBackend) providerBackendConstructor.newInstance(authConf,
                                                                                                 resourceName);
      if (providerBackend instanceof SentryGenericProviderBackend) {
        ((SentryGenericProviderBackend) providerBackend).setComponentType(COMPONENT_NAME);
        ((SentryGenericProviderBackend) providerBackend).setServiceName(instanceName);
      }

      // instantiate the configured policy engine
      Class<?> policyEngineClass = classLoader.loadClass(policyEngineName);
      Constructor<?> policyEngineConstructor = policyEngineClass.getDeclaredConstructor(ProviderBackend.class);
      policyEngineConstructor.setAccessible(true);
      PolicyEngine policyEngine = (PolicyEngine) policyEngineConstructor.newInstance(providerBackend);

      // Instantiate the configured authz provider
      Class<?> authProviderClass = classLoader.loadClass(authProviderName);
      Constructor<?> authzProviderConstructor = authProviderClass.getDeclaredConstructor(
        Configuration.class, String.class, PolicyEngine.class);
      authzProviderConstructor.setAccessible(true);
      return (AuthorizationProvider) authzProviderConstructor.newInstance(authConf, resourceName, policyEngine);
    } catch (Exception e) {
      throw Throwables.propagate(e);
    }
  }

  private List<TSentryPrivilege> getAllPrivileges(final Set<Role> roles, final String requestingUser) {
    return execute(new Command<List<TSentryPrivilege>>() {
      @Override
      public List<TSentryPrivilege> run(SentryGenericServiceClient client) throws Exception {
        final List<TSentryPrivilege> tSentryPrivileges = new ArrayList<>();
        for (Role role : roles) {
          tSentryPrivileges.addAll(client.listPrivilegesByRoleName(requestingUser, role.getName(),
                                                                   COMPONENT_NAME, instanceName));
        }
        return ImmutableList.copyOf(tSentryPrivileges);
      }
    });
  }

  @VisibleForTesting
  TSentryPrivilege toTSentryPrivilege(EntityId entityId, Action action) {
    List<org.apache.sentry.core.common.Authorizable> authorizables = toSentryAuthorizables(entityId);
    List<TAuthorizable> tAuthorizables = new ArrayList<>();
    for (org.apache.sentry.core.common.Authorizable authorizable : authorizables) {
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
   * Maps a {@link TAuthorizable sentry authorizable} to {@link EntityId}
   *
   * @param tAuthorizable the TAuthorizable which needs to be mapped to entity
   * @param parent the parent entity of this TAuthorizable
   * @return {@link EntityId} for the given {@link TAuthorizable}
   */
  private EntityId toEntityId(TAuthorizable tAuthorizable, @Nullable EntityId parent) {
    Authorizable authorizable = ModelAuthorizables.from(tAuthorizable.getType(), tAuthorizable.getName());
    switch (Authorizable.AuthorizableType.valueOf(tAuthorizable.getType())) {
      case INSTANCE:
        return new InstanceId(instanceName);
      case NAMESPACE:
        Namespace namespace = (Namespace) authorizable;
        return new NamespaceId(namespace.getName());
      case ARTIFACT:
        Artifact artifact = (Artifact) authorizable;
        Preconditions.checkNotNull(parent, "%s must have a parent", Authorizable.AuthorizableType.ARTIFACT);
        return ((NamespaceId) parent).artifact(artifact.getArtifactName(), artifact.getArtifactVersion());
      case APPLICATION:
        Application application = (Application) authorizable;
        Preconditions.checkNotNull(parent, "%s must have a parent", Authorizable.AuthorizableType.APPLICATION);
        return ((NamespaceId) parent).app(application.getName());
      case PROGRAM:
        Program program = (Program) authorizable;
        Preconditions.checkNotNull(parent, "%s must have a parent", Authorizable.AuthorizableType.PROGRAM);
        ApplicationId applicationId = (ApplicationId) parent;
        return applicationId.program(program.getProgramType(), program.getProgramName());
      case DATASET:
        Dataset dataset = (Dataset) authorizable;
        Preconditions.checkNotNull(parent, "%s must have a parent", Authorizable.AuthorizableType.DATASET);
        return ((NamespaceId) parent).dataset(dataset.getName());
      case STREAM:
        Stream stream = (Stream) authorizable;
        Preconditions.checkNotNull(parent, "%s must have a parent", Authorizable.AuthorizableType.STREAM);
        return ((NamespaceId) parent).stream(stream.getName());
      default:
        throw new IllegalArgumentException(String.format("Sentry Authorizable %s has invalid type %s",
                                                         tAuthorizable.getName(), tAuthorizable.getType()));
    }
  }

  /**
   * Maps {@link EntityId} to a {@link List} of {@link co.cask.cdap.security.authorization.sentry.model.Authorizable}
   * by recursively working its way from a given entity.
   *
   * @param entityId {@link EntityId} the entity which needs to be mapped to a list of authorizables
   * @param authorizables {@link List} of {@link co.cask.cdap.security.authorization.sentry.model.Authorizable} to
   * add authorizables to
   */
  private void toAuthorizables(EntityId entityId, List<org.apache.sentry.core.common.Authorizable> authorizables) {
    EntityType entityType = entityId.getEntity();
    switch (entityType) {
      case INSTANCE:
        authorizables.add(new Instance(((InstanceId) entityId).getInstance()));
        break;
      case NAMESPACE:
        toAuthorizables(new InstanceId(instanceName), authorizables);
        authorizables.add(new Namespace(((NamespaceId) entityId).getNamespace()));
        break;
      case ARTIFACT:
        ArtifactId artifactId = (ArtifactId) entityId;
        toAuthorizables(artifactId.getParent(), authorizables);
        authorizables.add(new Artifact(artifactId.getArtifact(), artifactId.getVersion()));
        break;
      case APPLICATION:
        ApplicationId applicationId = (ApplicationId) entityId;
        toAuthorizables(applicationId.getParent(), authorizables);
        authorizables.add(new Application((applicationId).getApplication()));
        break;
      case DATASET:
        DatasetId dataset = (DatasetId) entityId;
        toAuthorizables(dataset.getParent(), authorizables);
        authorizables.add(new Dataset((dataset).getDataset()));
        break;
      case STREAM:
        StreamId streamId = (StreamId) entityId;
        toAuthorizables(streamId.getParent(), authorizables);
        authorizables.add(new Stream((streamId).getStream()));
        break;
      case PROGRAM:
        ProgramId programId = (ProgramId) entityId;
        toAuthorizables(programId.getParent(), authorizables);
        authorizables.add(new Program(programId.getType(), programId.getProgram()));
        break;
      default:
        throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
    }
  }
}
