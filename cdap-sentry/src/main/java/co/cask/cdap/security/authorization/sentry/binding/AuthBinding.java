/*
 *
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

import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf.AuthzConfVars;
import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import co.cask.cdap.security.authorization.sentry.model.Instance;
import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.SentryUserException;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Created by rsinha on 2/29/16.
 */
public class AuthBinding {
  private static final Logger LOG = LoggerFactory.getLogger(AuthBinding.class);
  private static final String COMPONENT_TYPE = "cdap";

  private final Configuration authConf;
  private final AuthorizationProvider authProvider;
  private ProviderBackend providerBackend;
  private final String instanceName;
  private final String requestorName;

  private final ActionFactory actionFactory = ActionFactory.getInstance();

  public AuthBinding(Configuration authConf, String instanceName, String requestorName) throws Exception {
    this.authConf = authConf;
    this.instanceName = instanceName;
    this.requestorName = requestorName;
    this.authProvider = createAuthProvider();
  }

  /**
   * Instantiate the configured authz provider
   *
   * @return {@link AuthorizationProvider}
   */
  private AuthorizationProvider createAuthProvider() throws Exception {
    /**
     * get the authProvider class, policyEngine class, providerBackend class and resources from the
     * kafkaAuthConf config
     */
    String authProviderName =
      authConf.get(AuthzConfVars.AUTHZ_PROVIDER.getVar(),
                   AuthzConfVars.AUTHZ_PROVIDER.getDefault());
    String resourceName =
      authConf.get(AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getVar(),
                   AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getDefault());
    String providerBackendName =
      authConf.get(AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getVar(),
                   AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getDefault());
    String policyEngineName =
      authConf.get(AuthzConfVars.AUTHZ_POLICY_ENGINE.getVar(),
                   AuthzConfVars.AUTHZ_POLICY_ENGINE.getDefault());
    if (resourceName != null && resourceName.startsWith("classpath:")) {
      String resourceFileName = resourceName.substring("classpath:".length());
      resourceName = AuthorizationProvider.class.getClassLoader().getResource(resourceFileName).getPath();
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Using authorization provider " + authProviderName + " with resource "
                  + resourceName + ", policy engine " + policyEngineName + ", provider backend "
                  + providerBackendName);
    }

    // Instantiate the configured providerBackend
    Constructor<?> providerBackendConstructor =
      Class.forName(providerBackendName)
        .getDeclaredConstructor(Configuration.class, String.class);
    providerBackendConstructor.setAccessible(true);
    providerBackend =
      (ProviderBackend) providerBackendConstructor.newInstance(authConf, resourceName);
    if (providerBackend instanceof SentryGenericProviderBackend) {
      ((SentryGenericProviderBackend) providerBackend).setComponentType(COMPONENT_TYPE);
      ((SentryGenericProviderBackend) providerBackend).setServiceName(instanceName);
    }

    // Instantiate the configured policyEngine
    Constructor<?> policyConstructor =
      Class.forName(policyEngineName).getDeclaredConstructor(ProviderBackend.class);
    policyConstructor.setAccessible(true);
    PolicyEngine policyEngine =
      (PolicyEngine) policyConstructor.newInstance(providerBackend);

    // Instantiate the configured authProvider
    Constructor<?> constructor =
      Class.forName(authProviderName).getDeclaredConstructor(Configuration.class, String.class,
                                                             PolicyEngine.class);
    constructor.setAccessible(true);
    return (AuthorizationProvider) constructor.newInstance(authConf, resourceName, policyEngine);
  }

  public void grant(final EntityId entityId, Principal principal, Set<Action> set) {
    Preconditions.checkArgument(principal.getType() == Principal.PrincipalType.ROLE, "Actions can only granted to a" +
      " role. Please add the user/group to an existing/new role and grant action to the role.");
    final String role = principal.getName();
    if (!roleExists(role)) {
      throw new IllegalArgumentException("Can give action for non-existent Role: " + role);
    }
    for (final Action action : set) {
      execute(new Command<Void>() {
        @Override
        public Void run(SentryGenericServiceClient client) throws Exception {
          client.grantPrivilege(
            requestorName, role, COMPONENT_TYPE, toTSentryPrivilege(action, entityId));
          return null;
        }
      });
    }
  }

  private TSentryPrivilege toTSentryPrivilege(Action action, EntityId entityId) {
    final List<Authorizable> authorizables = EntityToAuthMapper.convertResourceToAuthorizable(entityId);
    final List<TAuthorizable> tAuthorizables = new ArrayList<>();
    for (Authorizable authorizable : authorizables) {
      tAuthorizables.add(new TAuthorizable(authorizable.getTypeName(), authorizable.getName()));
    }
    return new TSentryPrivilege(COMPONENT_TYPE, instanceName, tAuthorizables,
                                action.name());
  }

  private SentryGenericServiceClient getClient() throws Exception {
    return SentryGenericServiceClientFactory.create(this.authConf);
  }

  /**
   * A Command is a closure used to pass a block of code from individual
   * functions to execute, which centralizes connection error
   * handling. Command is parameterized on the return type of the function.
   */
  private interface Command<T> {
    T run(SentryGenericServiceClient client) throws Exception;
  }

  private <T> T execute(Command<T> cmd) throws RuntimeException {
    SentryGenericServiceClient client = null;
    try {
      client = getClient();
      return cmd.run(client);
    } catch (SentryUserException ex) {
      String msg = "Unable to excute command on sentry server: " + ex.getMessage();
      LOG.error(msg, ex);
      throw new RuntimeException(msg, ex);
    } catch (Exception ex) {
      String msg = "Unable to obtain client:" + ex.getMessage();
      LOG.error(msg, ex);
      throw new RuntimeException(msg, ex);
    } finally {
      if (client != null) {
        client.close();
      }
    }
  }

  private boolean roleExists(String role) {
    return getAllRoles().contains(role);
  }

  private List<String> getAllRoles() {
    final List<String> roles = new ArrayList<>();
    execute(new Command<Void>() {
      @Override
      public Void run(SentryGenericServiceClient client) throws Exception {
        for (TSentryRole tSentryRole : client.listAllRoles(requestorName, COMPONENT_TYPE)) {
          roles.add(tSentryRole.getRoleName());
        }
        return null;
      }
    });

    return roles;
  }

  /**
   * Authorize access to a CDAP entity
   */
  public boolean authorize(EntityId entityId, Principal principal, Action action) {
    List<Authorizable> authorizables = EntityToAuthMapper.convertResourceToAuthorizable(entityId);
    Set<ActionFactory.Action> actions = Sets.newHashSet(actionFactory.getActionByName(action.name()));
    LOG.info("### Trying to talk to AuthProvider from AuthBinding to get permission");
    Instance instance = new Instance(instanceName);
    if (!authorizables.contains(instance)) {
      authorizables.add(0, instance);
    }
    boolean hasAccess = authProvider.hasAccess(new Subject(principal.getName()),
                                               authorizables, actions, ActiveRoleSet.ALL);
    LOG.info("### hasAccess in the AuthBinding returned with {}", hasAccess);
    return hasAccess;
  }
}
