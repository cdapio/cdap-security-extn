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
import com.google.common.collect.Sets;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.core.common.ActiveRoleSet;
import org.apache.sentry.core.common.Authorizable;
import org.apache.sentry.core.common.Subject;
import org.apache.sentry.policy.common.PolicyEngine;
import org.apache.sentry.provider.common.AuthorizationProvider;
import org.apache.sentry.provider.common.ProviderBackend;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Constructor;
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

  private final ActionFactory actionFactory = ActionFactory.getInstance();

  public AuthBinding(Configuration authConf) throws Exception {
    this.authConf = authConf;
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
    String instanceName = authConf.get(AuthzConfVars.AUTHZ_INSTANCE_NAME.getVar());
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
      (ProviderBackend) providerBackendConstructor.newInstance(new Object[]{authConf,
        resourceName});
    if (providerBackend instanceof SentryGenericProviderBackend) {
      ((SentryGenericProviderBackend) providerBackend).setComponentType(COMPONENT_TYPE);
      ((SentryGenericProviderBackend) providerBackend).setServiceName("kafka" + instanceName);
    }

    // Instantiate the configured policyEngine
    Constructor<?> policyConstructor =
      Class.forName(policyEngineName).getDeclaredConstructor(ProviderBackend.class);
    policyConstructor.setAccessible(true);
    PolicyEngine policyEngine =
      (PolicyEngine) policyConstructor.newInstance(new Object[]{providerBackend});

    // Instantiate the configured authProvider
    Constructor<?> constructor =
      Class.forName(authProviderName).getDeclaredConstructor(Configuration.class, String.class,
                                                             PolicyEngine.class);
    constructor.setAccessible(true);
    return (AuthorizationProvider) constructor.newInstance(new Object[]{authConf, resourceName,
      policyEngine});
  }

  /**
   * Authorize access to a Kafka privilege
   */
  public boolean authorize(EntityId entityId, Principal principal, Action action) {
    List<Authorizable> authorizables = EntityToAuthMapper.convertResourceToAuthorizable(entityId);
    Set<ActionFactory.Action> actions = Sets.newHashSet(actionFactory.getActionByName(action.name()));
    return authProvider.hasAccess(new Subject(principal.getName()), authorizables, actions, ActiveRoleSet.ALL);
  }
}
