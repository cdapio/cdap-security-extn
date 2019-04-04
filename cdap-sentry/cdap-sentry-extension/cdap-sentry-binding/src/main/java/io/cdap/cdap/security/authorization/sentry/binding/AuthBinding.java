/*
 * Copyright 2016-2019 Cask Data, Inc.
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

import io.cdap.cdap.proto.ProgramType;
import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.proto.security.Privilege;
import io.cdap.cdap.proto.security.Role;
import io.cdap.cdap.security.authorization.sentry.binding.conf.AuthConf;
import io.cdap.cdap.security.authorization.sentry.binding.conf.AuthConf.AuthzConfVars;
import io.cdap.cdap.security.authorization.sentry.model.ActionFactory;
import io.cdap.cdap.security.authorization.sentry.model.Application;
import io.cdap.cdap.security.authorization.sentry.model.Artifact;
import io.cdap.cdap.security.authorization.sentry.model.Authorizable;
import io.cdap.cdap.security.authorization.sentry.model.Dataset;
import io.cdap.cdap.security.authorization.sentry.model.DatasetModule;
import io.cdap.cdap.security.authorization.sentry.model.DatasetType;
import io.cdap.cdap.security.authorization.sentry.model.Instance;
import io.cdap.cdap.security.authorization.sentry.model.Namespace;
import io.cdap.cdap.security.authorization.sentry.model.Program;
import io.cdap.cdap.security.authorization.sentry.model.SecureKey;
import io.cdap.cdap.security.authorization.sentry.model.Stream;
import io.cdap.cdap.security.authorization.sentry.policy.ModelAuthorizables;
import io.cdap.cdap.security.authorization.sentry.policy.PrivilegeValidator;
import io.cdap.cdap.security.spi.authorization.AlreadyExistsException;
import io.cdap.cdap.security.spi.authorization.BadRequestException;
import io.cdap.cdap.security.spi.authorization.NotFoundException;
import io.cdap.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.policy.common.PolicyEngine;
import org.apache.sentry.provider.common.AuthorizationProvider;
import org.apache.sentry.provider.common.ProviderBackend;
import org.apache.sentry.provider.db.SentryAccessDeniedException;
import org.apache.sentry.provider.db.SentryAlreadyExistsException;
import org.apache.sentry.provider.db.SentryInvalidInputException;
import org.apache.sentry.provider.db.SentryNoSuchObjectException;
import org.apache.sentry.provider.db.SentryThriftAPIMismatchException;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClient;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClientFactory;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryGrantOption;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nullable;

/**
 * This class instantiate the {@link AuthorizationProvider} configured in {@link AuthConf} and is responsible for
 * performing different authorization operation on CDAP entities by mapping them to authorizables
 * {@link #toSentryAuthorizables(io.cdap.cdap.proto.security.Authorizable)}
 */
class AuthBinding {
  private static final Logger LOG = LoggerFactory.getLogger(AuthBinding.class);
  private static final String COMPONENT_NAME = "cdap";
  private final AuthConf authConf;
  private final AuthorizationProvider authProvider;
  private final String instanceName;
  private final String sentryAdminGroup;

  // Cache for principal to groups the principal is part of
  private final LoadingCache<Principal, Set<String>> groupCache;
  // Cache for group to set of roles the group is part of
  private final LoadingCache<String, Set<Role>> roleCache;
  // Cache for role to set of policies for the role
  private final LoadingCache<Role, Set<WildcardPolicy>> policyCache;

  AuthBinding(String sentrySite, final String instanceName, final String sentryAdminGroup,
              int cacheTtlSecs, int cacheMaxEntries) {
    this.authConf = initAuthzConf(sentrySite);
    this.instanceName = instanceName;
    this.authProvider = createAuthProvider();
    this.sentryAdminGroup = sentryAdminGroup;

    groupCache = CacheBuilder.newBuilder()
      .expireAfterWrite(cacheTtlSecs, TimeUnit.SECONDS)
      .maximumSize(cacheMaxEntries)
      .build(new CacheLoader<Principal, Set<String>>() {
        @SuppressWarnings("NullableProblems")
        @Override
        public Set<String> load(Principal principal) throws Exception {
          LOG.trace("Group cache miss for principal {}", principal);
          return fetchGroups(principal);
        }
      });

    roleCache = CacheBuilder.newBuilder()
      .expireAfterWrite(cacheTtlSecs, TimeUnit.SECONDS)
      .maximumSize(cacheMaxEntries)
      .build(new CacheLoader<String, Set<Role>>() {
        @SuppressWarnings("NullableProblems")
        @Override
        public Set<Role> load(final String group) throws Exception {
          LOG.trace("Role cache miss for group {}", group);
          return fetchRoles(group);
        }
      });

    policyCache = CacheBuilder.newBuilder()
      .expireAfterWrite(cacheTtlSecs, TimeUnit.SECONDS)
      .maximumSize(cacheMaxEntries)
      .build(new CacheLoader<Role, Set<WildcardPolicy>>() {
        @SuppressWarnings("NullableProblems")
        @Override
        public Set<WildcardPolicy> load(final Role role) throws Exception {
          LOG.trace("Policy cache miss for role {}", role);
          return fetchPolicies(role);
        }
      });
  }

  /**
   * @return policies for the given principal
   */
  Set<WildcardPolicy> getPolicies(Principal principal) throws Exception {
    Set<Role> roles = getRoles(principal, sentryAdminGroup);

    Set<WildcardPolicy> policies = new HashSet<>();
    for (Role role : roles) {
      Set<WildcardPolicy> policy = policyCache.get(role);
      policies.addAll(policy);
    }
    return Collections.unmodifiableSet(policies);
  }

  /**
   * Grants the specified {@link Action actions} on the specified {@link io.cdap.cdap.proto.security.Authorizable}
   * to the specified {@link Role}.
   *
   * @param authorizable the authorizable on which the actions need to be granted
   * @param role the role to which the actions need to granted
   * @param actions the actions which need to be granted
   * @param requestingUser the user executing this operation
   * @throws Exception when there is any exception while running the client command to grant for user
   */
  void grant(final io.cdap.cdap.proto.security.Authorizable authorizable, final Role role, final Set<Action> actions,
             final String requestingUser) throws Exception {
    LOG.debug("Granting actions {} on entity {} for role {}; Requesting user: {}",
              actions, authorizable, role, requestingUser);
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        for (final Action action : actions) {
          client.grantPrivilege(requestingUser, role.getName(), COMPONENT_NAME, toTSentryPrivilege(authorizable,
                                                                                                   action));
        }
        return null;
      }
    });
  }

  /**
   * Revokes a {@link Role role's} authorization to perform a set of {@link Action actions} on
   * an {@link io.cdap.cdap.proto.security.Authorizable}.
   *
   * @param authorizable the {@link io.cdap.cdap.proto.security.Authorizable} whose {@link Action actions} are to be
   * revoked
   * @param role the {@link Role} from which the actions needs to be revoked
   * @param actions the set of {@link Action actions} to revoke
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for dropping privileges
   */
  void revoke(final io.cdap.cdap.proto.security.Authorizable authorizable, final Role role, final Set<Action> actions,
              final String requestingUser) throws Exception {
    LOG.debug("Revoking actions {} on entity {} from role {}; Requesting user: {}",
              actions, authorizable, role, requestingUser);
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        for (final Action action : actions) {
          client.revokePrivilege(requestingUser, role.getName(), COMPONENT_NAME,
                                 toTSentryPrivilege(authorizable, action));
        }
        return null;
      }
    });
  }

  /**
   * Revoke all privileges on a CDAP authorizable. This is a privileged operation executed either to clean up orphaned
   * privileges on an entity before creating it, or to revoke all privileges on an entity once the entity is deleted.
   * This operation is executed as the {@link #sentryAdminGroup}.
   *
   * @param authorizable the {@link io.cdap.cdap.proto.security.Authorizable} on which all privileges have to be revoked
   * @throws Exception if there was any exception while running the client command for dropping privileges
   */
  void revoke(io.cdap.cdap.proto.security.Authorizable authorizable) throws Exception {
    revoke(authorizable, sentryAdminGroup);
  }

  /**
   * Revokes all {@link Principal principals'} authorization to perform any {@link Action} on the given
   * {@link io.cdap.cdap.proto.security.Authorizable}.
   *
   * @param authorizable the {@link io.cdap.cdap.proto.security.Authorizable} on which all {@link Action actions} are to
   * be revoked
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for dropping privileges
   */
  private void revoke(io.cdap.cdap.proto.security.Authorizable authorizable, final String requestingUser)
    throws Exception {
    Set<Role> allRoles = listAllRoles();
    final List<TSentryPrivilege> allPrivileges = getAllPrivileges(allRoles);
    final List<TAuthorizable> tAuthorizables = toTAuthorizable(authorizable);
    LOG.debug("Revoking all actions for all users from entity {}; Requesting user: {}", authorizable, requestingUser);
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
   * Lists {@link Privilege privileges} for the given {@link Principal}
   *
   * @param principal the principal for which the privileges has to be listed
   * @return {@link Set} of {@link Privilege privilege} for the given principal
   * @throws Exception if there was any exception while running the client command getting roles and privileges
   */
  Set<Privilege> listPrivileges(Principal principal) throws Exception {
    Set<Role> roles = getRoles(principal, sentryAdminGroup);
    LOG.debug("Listing all privileges for {};", principal);
    List<TSentryPrivilege> allPrivileges = getAllPrivileges(roles);
    return toPrivileges(allPrivileges);
  }

  @VisibleForTesting
  Set<Privilege> toPrivileges(Collection<TSentryPrivilege> allPrivileges) {
    Set<Privilege> privileges = new HashSet<>();
    for (TSentryPrivilege sentryPrivilege : allPrivileges) {
      List<TAuthorizable> authorizables = sentryPrivilege.getAuthorizables();
      if (authorizables.isEmpty()) {
        continue;
      }
      EntityType entityType = null;
      Map<EntityType, String> entityParts = new LinkedHashMap<>();
      for (TAuthorizable authorizable : authorizables) {
        // we only need to keep the final entity type since authorizable are ordered top down and the last entity
        // type is the entity type of authorizable
        entityType = addToEntityParts(authorizable, entityParts);
      }
      // for entity type other than instance we don't include instance in the Authorizable string as in cdap entities
      // don't inherit instance.
      Preconditions.checkNotNull(entityType, "Failed to determine entityType for the sentry authorizable %s",
                                 authorizables);
      if (!entityType.equals(EntityType.INSTANCE)) {
        entityParts.remove(EntityType.INSTANCE);
      }
      privileges.add(new Privilege(new io.cdap.cdap.proto.security.Authorizable(entityType, entityParts),
                                   Action.valueOf(sentryPrivilege.getAction().toUpperCase())));
    }
    return Collections.unmodifiableSet(privileges);
  }

  /**
   * Creates the specified role.
   *
   * @param role the role to be created
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for creating role for user
   */
  void createRole(final Role role, final String requestingUser) throws Exception {
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
   * @throws Exception if there was any exception while running the client command for dropping the role for user
   */
  void dropRole(final Role role, final String requestingUser) throws Exception {
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.dropRole(requestingUser, role.getName(), COMPONENT_NAME);
        LOG.debug("Dropped role {}; Requesting user: {}", role, requestingUser);
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
   * @throws Exception if there was any exception while running the client command for listing roles
   */
  Set<Role> listRolesForGroup(Principal principal, final String requestingUser) throws Exception {
    return getRoles(principal, requestingUser);
  }

  /**
   * Lists all roles
   *
   * @return {@link Set} of all {@link Role}
   * @throws Exception if there were any exception while running client commdn to listing all roles
   */
  Set<Role> listAllRoles() throws Exception {
    return getRoles(null, sentryAdminGroup);
  }

  /**
   * Add a role to group principal
   *
   * @param role the role which needs to be added to the group principal
   * @param principal the group principal to which the role needs to be added
   * @param requestingUser the user executing this operation
   * @throws Exception if there was any exception while running the client command for adding role to group
   */
  void addRoleToGroup(final Role role, final Principal principal,
                      final String requestingUser) throws Exception {
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.addRoleToGroups(requestingUser, role.getName(), COMPONENT_NAME,
                               ImmutableSet.of(principal.getName()));
        LOG.debug("Added role {} to group {} for the requested user {}", role, principal, requestingUser);
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
   * @throws Exception if there was exception while running the client command to remove role from group
   */
  void removeRoleFromGroup(final Role role, final Principal principal,
                           final String requestingUser) throws Exception {
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        client.deleteRoleToGroups(requestingUser, role.getName(), COMPONENT_NAME,
                                  ImmutableSet.of(principal.getName()));
        LOG.debug("Dropped role {} from group {} for the requested user {}", role, principal, requestingUser);
        return null;
      }
    });
  }

  // just a helper for unit tests
  @VisibleForTesting
  List<org.apache.sentry.core.common.Authorizable> toSentryAuthorizables(EntityId entityId) {
    return toSentryAuthorizables(io.cdap.cdap.proto.security.Authorizable.fromEntityId(entityId));
  }

  /**
   * Maps the given {@link EntityId} to {@link Authorizable}. To see a valid set of {@link Authorizable}
   * please see {@link PrivilegeValidator} which is responsible for validating these authorizables positions and action.
   *
   * @param authorizable the {@link EntityId} which needs to be mapped to list of {@link Authorizable}
   * @return a {@link List} of {@link Authorizable} which represents the given {@link EntityId}
   */
  @VisibleForTesting
  private List<org.apache.sentry.core.common.Authorizable>
  toSentryAuthorizables(final io.cdap.cdap.proto.security.Authorizable authorizable) {
    List<org.apache.sentry.core.common.Authorizable> authorizables = new LinkedList<>();
    toSentryAuthorizables(authorizable.getEntityType(), authorizable, authorizables);
    return authorizables;
  }

  private Set<Role> getRoles(@Nullable final Principal principal, final String requestingUser) throws Exception {
    // if the specified principal is non-null and is a role, then we just return a singleton set containing that role
    if (principal != null && Principal.PrincipalType.ROLE == principal.getType()) {
      return Collections.singleton(new Role(principal.getName()));
    }

    Set<Role> roles;
    if (principal == null) {
      roles = new HashSet<>();
      Set<TSentryRole> tSentryRoles = execute(new Command<Set<TSentryRole>>() {
        @Override
        public Set<TSentryRole> run(SentryGenericServiceClient client) throws Exception {
          return client.listAllRoles(requestingUser, COMPONENT_NAME);
        }
      });
      for (TSentryRole tSentryRole : tSentryRoles) {
        roles.add(new Role(tSentryRole.getRoleName()));
      }
      LOG.debug("Listed all roles {}; Requesting user: {}", roles, requestingUser);
    } else {
      if (principal.getType().equals(Principal.PrincipalType.USER)) {
        // for a user get all the groups and their roles
        Set<String> groups = groupCache.get(principal);
        LOG.debug("Got groups {} for principal {}", groups, principal);
        roles = new HashSet<>();
        for (String group : groups) {
          roles.addAll(roleCache.get(group));
        }
      } else if (principal.getType().equals(Principal.PrincipalType.GROUP)) {
        roles = roleCache.get(principal.getName());
      } else {
        throw new IllegalArgumentException(String.format("Cannot list roles for %s. Roles can only listed for %s or %s",
                                                         principal, Principal.PrincipalType.USER,
                                                         Principal.PrincipalType.GROUP));
      }
      LOG.debug("Listed roles {} for principal {}; Requesting user: {}", roles, principal, requestingUser);
    }
    return Collections.unmodifiableSet(roles);
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

  private List<TSentryPrivilege> getAllPrivileges(final Set<Role> roles) throws Exception {
    return execute(new Command<List<TSentryPrivilege>>() {
      @Override
      public List<TSentryPrivilege> run(SentryGenericServiceClient client) throws Exception {
        final List<TSentryPrivilege> tSentryPrivileges = new ArrayList<>();
        for (Role role : roles) {
          tSentryPrivileges.addAll(client.listPrivilegesByRoleName(sentryAdminGroup, role.getName(),
                                                                   COMPONENT_NAME, instanceName));
        }
        return Collections.unmodifiableList(tSentryPrivileges);
      }
    });
  }

  // just a helper for unit tests
  @VisibleForTesting
  TSentryPrivilege toTSentryPrivilege(EntityId entityId, Action action) {
    return toTSentryPrivilege(io.cdap.cdap.proto.security.Authorizable.fromEntityId(entityId), action);
  }

  @VisibleForTesting
  private TSentryPrivilege toTSentryPrivilege(io.cdap.cdap.proto.security.Authorizable authorizable, Action action) {
    List<TAuthorizable> tAuthorizables = toTAuthorizable(authorizable);
    TSentryPrivilege tSentryPrivilege = new TSentryPrivilege(COMPONENT_NAME, instanceName,
                                                             tAuthorizables, action.name());
    // CDAP-9029 Set grant options to true so that sentry will allow the privileges to be passed on to some other user
    // Setting it true for all privileges gives to a user is fine as we don't rely on this setting. While doing
    // grant CDAP enforces ADMIN on the entity.
    tSentryPrivilege.setGrantOption(TSentryGrantOption.TRUE);
    return tSentryPrivilege;
  }

  private List<TAuthorizable> toTAuthorizable(io.cdap.cdap.proto.security.Authorizable authorizable) {
    List<org.apache.sentry.core.common.Authorizable> sentryAuthorizables = toSentryAuthorizables(authorizable);
    List<TAuthorizable> tAuthorizables = new ArrayList<>();
    for (org.apache.sentry.core.common.Authorizable authz : sentryAuthorizables) {
      tAuthorizables.add(new TAuthorizable(authz.getTypeName(), authz.getName()));
    }
    return tAuthorizables;
  }

  private <T> T execute(Command<T> cmd) throws Exception {
    try {
      SentryGenericServiceClient client = getClient();
      try {
        return cmd.run(client);
      } finally {
        client.close();
      }
    } catch (Exception e) {
      // map sentry exceptions to appropriate cdap-security exceptions
      if (e instanceof SentryAccessDeniedException) {
        throw new UnauthorizedException(e.getMessage());
      } else if (e instanceof SentryNoSuchObjectException) {
        throw new NotFoundException(e.getMessage());
      } else if (e instanceof SentryAlreadyExistsException) {
        throw new AlreadyExistsException(e.getMessage());
      } else if (e instanceof SentryInvalidInputException || e instanceof SentryThriftAPIMismatchException) {
        throw new BadRequestException(e.getMessage());
      } else {
        throw e;
      }
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
    // TODO: Cache the client
    return SentryGenericServiceClientFactory.create(authConf);
  }

  private EntityType addToEntityParts(TAuthorizable tAuthorizable, Map<EntityType, String> entityParts) {
    Authorizable sentryAuthorizable = ModelAuthorizables.from(tAuthorizable.getType(), tAuthorizable.getName());
    switch (Authorizable.AuthorizableType.valueOf(tAuthorizable.getType())) {
      case INSTANCE:
        entityParts.put(EntityType.INSTANCE, instanceName);
        return EntityType.INSTANCE;
      case NAMESPACE:
        Namespace namespace = (Namespace) sentryAuthorizable;
        entityParts.put(EntityType.NAMESPACE, namespace.getName());
        return EntityType.NAMESPACE;
      case ARTIFACT:
        Artifact artifact = (Artifact) sentryAuthorizable;
        Preconditions.checkArgument(entityParts.containsKey(EntityType.NAMESPACE),
                                    "Artifact %s must belong to a namespace. Currently known entity parts are %s",
                                    artifact, entityParts);
        entityParts.put(EntityType.ARTIFACT, artifact.getName());
        return EntityType.ARTIFACT;
      case APPLICATION:
        Application application = (Application) sentryAuthorizable;
        Preconditions.checkArgument(entityParts.containsKey(EntityType.NAMESPACE),
                                    "Application %s must belong to a namespace. Currently known entity parts are %s",
                                    application, entityParts);
        entityParts.put(EntityType.APPLICATION, application.getName());
        return EntityType.APPLICATION;
      case PROGRAM:
        Program program = (Program) sentryAuthorizable;
        Preconditions.checkArgument(entityParts.containsKey(EntityType.APPLICATION),
                                    "Program %s must belong to a application. Currently known entity parts are %s",
                                    program, entityParts);
        StringBuilder builder = new StringBuilder();
        if (program.getProgramType() != null) {
          builder.append(program.getProgramType().getPrettyName().toLowerCase());
          builder.append(EntityId.IDSTRING_PART_SEPARATOR);
        }
        builder.append(program.getProgramName());
        entityParts.put(EntityType.PROGRAM, builder.toString());
        return EntityType.PROGRAM;
      case DATASET:
        Dataset dataset = (Dataset) sentryAuthorizable;
        Preconditions.checkArgument(entityParts.containsKey(EntityType.NAMESPACE),
                                    "Dataset %s must belong to a namespace.  Currently known entity parts are %s",
                                    dataset, entityParts);
        entityParts.put(EntityType.DATASET, dataset.getName());
        return EntityType.DATASET;
      case DATASET_MODULE:
        DatasetModule datasetModule = (DatasetModule) sentryAuthorizable;
        Preconditions.checkArgument(entityParts.containsKey(EntityType.NAMESPACE),
                                    "DatasetModule %s must belong to a namespace. Currently known entity parts are %s",
                                    datasetModule, entityParts);
        entityParts.put(EntityType.DATASET_MODULE, datasetModule.getName());
        return EntityType.DATASET_MODULE;
      case DATASET_TYPE:
        DatasetType datasetType = (DatasetType) sentryAuthorizable;
        Preconditions.checkArgument(entityParts.containsKey(EntityType.NAMESPACE),
                                    "DatasetType %s must belong to a namespace. Currently known entity parts are %s",
                                    datasetType, entityParts);
        entityParts.put(EntityType.DATASET_TYPE, datasetType.getName());
        return EntityType.DATASET_TYPE;
      case STREAM:
        Stream stream = (Stream) sentryAuthorizable;
        Preconditions.checkArgument(entityParts.containsKey(EntityType.NAMESPACE),
                                    "Stream %s must belong to a namespace. Currently known entity parts are %s",
                                    stream, entityParts);
        entityParts.put(EntityType.STREAM, stream.getName());
        return EntityType.STREAM;
      case SECUREKEY:
        SecureKey secureKey = (SecureKey) sentryAuthorizable;
        Preconditions.checkArgument(entityParts.containsKey(EntityType.NAMESPACE),
                                    "SecureKey %s must belong to a namespace. Currently known entity parts are %s",
                                    secureKey, entityParts);
        entityParts.put(EntityType.SECUREKEY, secureKey.getName());
        return EntityType.SECUREKEY;
      case PRINCIPAL:
        io.cdap.cdap.security.authorization.sentry.model.Principal principal =
          (io.cdap.cdap.security.authorization.sentry.model.Principal) sentryAuthorizable;
        entityParts.put(EntityType.KERBEROSPRINCIPAL, principal.getName());
        return EntityType.KERBEROSPRINCIPAL;
      default:
        throw new IllegalArgumentException(String.format("Sentry Authorizable %s has invalid type %s",
                                                         tAuthorizable.getName(), tAuthorizable.getType()));
    }
  }

  /**
   * Maps {@link io.cdap.cdap.proto.security.Authorizable} to a {@link List} of {@link Authorizable}
   * by recursively working its way from a given entity.
   *
   * @param curType entity type
   * @param authorizable the cdap authorizable which needs to be mapped
   * @param sentryAuthorizables list of sentry authorizable
   */
  void toSentryAuthorizables(EntityType curType, io.cdap.cdap.proto.security.Authorizable authorizable,
                             List<? super Authorizable> sentryAuthorizables) {
    switch (curType) {
      case INSTANCE:
        sentryAuthorizables.add(new Instance(authorizable.getEntityParts().get(EntityType.INSTANCE)));
        break;
      case NAMESPACE:
        sentryAuthorizables.add(new Instance(instanceName));
        sentryAuthorizables.add(new Namespace(authorizable.getEntityParts().get(curType)));
        break;
      case ARTIFACT:
        toSentryAuthorizables(EntityType.NAMESPACE, authorizable, sentryAuthorizables);
        sentryAuthorizables.add(new Artifact(authorizable.getEntityParts().get(curType)));
        break;
      case APPLICATION:
        toSentryAuthorizables(EntityType.NAMESPACE, authorizable, sentryAuthorizables);
        sentryAuthorizables.add(new Application(authorizable.getEntityParts().get(curType)));
        break;
      case DATASET:
        toSentryAuthorizables(EntityType.NAMESPACE, authorizable, sentryAuthorizables);
        sentryAuthorizables.add(new Dataset(authorizable.getEntityParts().get(curType)));
        break;
      case DATASET_MODULE:
        toSentryAuthorizables(EntityType.NAMESPACE, authorizable, sentryAuthorizables);
        sentryAuthorizables.add(new DatasetModule(authorizable.getEntityParts().get(curType)));
        break;
      case DATASET_TYPE:
        toSentryAuthorizables(EntityType.NAMESPACE, authorizable, sentryAuthorizables);
        sentryAuthorizables.add(new DatasetType(authorizable.getEntityParts().get(curType)));
        break;
      case STREAM:
        toSentryAuthorizables(EntityType.NAMESPACE, authorizable, sentryAuthorizables);
        sentryAuthorizables.add(new Stream(authorizable.getEntityParts().get(curType)));
        break;
      case PROGRAM:
        toSentryAuthorizables(EntityType.APPLICATION, authorizable, sentryAuthorizables);
        String[] programDetails = authorizable.getEntityParts().get(curType).split("\\.");
        if (programDetails.length == 1) {
          // We allow * when program type is not provided
          sentryAuthorizables.add(new Program(programDetails[0]));
        } else {
          sentryAuthorizables.add(new Program(ProgramType.valueOf(programDetails[0].toUpperCase()), programDetails[1]));
        }
        break;
      case SECUREKEY:
        toSentryAuthorizables(EntityType.NAMESPACE, authorizable, sentryAuthorizables);
        sentryAuthorizables.add(new SecureKey(authorizable.getEntityParts().get(curType)));
        break;
      case KERBEROSPRINCIPAL:
        sentryAuthorizables.add(new Instance(instanceName));
        sentryAuthorizables.add(new io.cdap.cdap.security.authorization.sentry.model.Principal(
          authorizable.getEntityParts().get(curType)));
        break;
      default:
        throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s",
                                                         authorizable.getEntityParts(), authorizable.getEntityType()));
    }
  }

  Set<ActionFactory.Action> toSentryActions(Set<Action> actions) {
    Set<ActionFactory.Action> sentryActions = new HashSet<>(actions.size());
    for (Action action : actions) {
      sentryActions.add(new ActionFactory.Action(action.name()));
    }
    return Collections.unmodifiableSet(sentryActions);
  }

  private static List<Authorizable> toSentryAuthorizables(List<TAuthorizable> tAuthorizables) {
    List<Authorizable> authorizables = new ArrayList<>(tAuthorizables.size());
    for (TAuthorizable tAuthorizable : tAuthorizables) {
      authorizables.add(ModelAuthorizables.from(tAuthorizable.getType(), tAuthorizable.getName()));
    }
    return authorizables;
  }

  private Set<String> fetchGroups(Principal principal) {
    return authProvider.getGroupMapping().getGroups(principal.getName());
  }

  private Set<Role> fetchRoles(final String group) throws Exception {
    Set<TSentryRole> tSentryRoles = execute(new Command<Set<TSentryRole>>() {
      @Override
      public Set<TSentryRole> run(SentryGenericServiceClient client) throws Exception {
        return client.listRolesByGroupName(sentryAdminGroup, group, COMPONENT_NAME);
      }
    });
    Set<Role> roles = new HashSet<>();
    for (TSentryRole tSentryRole : tSentryRoles) {
      roles.add(new Role(tSentryRole.getRoleName()));
    }
    return roles;
  }

  private Set<WildcardPolicy> fetchPolicies(final Role role) throws Exception {
    Set<TSentryPrivilege> sentryPrivileges = execute(new Command<Set<TSentryPrivilege>>() {
      @Override
      public Set<TSentryPrivilege> run(SentryGenericServiceClient client) throws Exception {
        return client.listPrivilegesByRoleName(sentryAdminGroup, role.getName(), COMPONENT_NAME, instanceName);
      }
    });

    if (sentryPrivileges == null) {
      LOG.debug("Got empty set of policies for role {}", role);
      return Collections.emptySet();
    }

    Set<WildcardPolicy> policies = new HashSet<>(sentryPrivileges.size());
    for (TSentryPrivilege sentryPrivilege : sentryPrivileges) {
      policies.add(new WildcardPolicy(toSentryAuthorizables(sentryPrivilege.getAuthorizables()),
                                      new ActionFactory.Action(sentryPrivilege.getAction())));
    }

    LOG.debug("Got policies {} for role {}", policies, role);
    return Collections.unmodifiableSet(policies);
  }
}
