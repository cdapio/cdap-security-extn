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

package co.cask.cdap.security.authorization.sentry.policy;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.apache.sentry.core.common.ActiveRoleSet;
import org.apache.sentry.core.common.Authorizable;
import org.apache.sentry.core.common.SentryConfigurationException;
import org.apache.sentry.policy.common.PolicyEngine;
import org.apache.sentry.policy.common.Privilege;
import org.apache.sentry.policy.common.PrivilegeFactory;
import org.apache.sentry.provider.common.ProviderBackend;
import org.apache.sentry.provider.common.ProviderBackendContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * A Simple policy engine which is used to validate privilege requests
 */
public class SimplePolicyEngine implements PolicyEngine {
  private static final Logger LOG = LoggerFactory.getLogger(SimplePolicyEngine.class);

  private final ProviderBackend providerBackend;

  public SimplePolicyEngine(ProviderBackend providerBackend) {
    this.providerBackend = providerBackend;
    ProviderBackendContext context = new ProviderBackendContext();
    context.setAllowPerDatabase(false);

    // Set all the validator to be used to validate the privileges here
    context.setValidators(ImmutableList.<org.apache.sentry.policy.common.PrivilegeValidator>of(
      new PrivilegeValidator()));
    try {
      this.providerBackend.initialize(context);
    } catch (Exception e) {
      close();
      throw e;
    }
  }

  @Override
  public PrivilegeFactory getPrivilegeFactory() {
    return new PrivilegeFactory() {
      @Override
      public Privilege createPrivilege(String permission) {
        return new WildcardPrivilege(permission);
      }
    };
  }

  @Override
  public ImmutableSet<String> getAllPrivileges(Set<String> set,
                                               ActiveRoleSet activeRoleSet) throws SentryConfigurationException {
    return getPrivileges(set, activeRoleSet);
  }

  @Override
  public ImmutableSet<String> getPrivileges(Set<String> set, ActiveRoleSet activeRoleSet,
                                            Authorizable... authorizables) throws SentryConfigurationException {

    LOG.debug("Getting permissions for {}", set);
    ImmutableSet<String> result = providerBackend.getPrivileges(set, activeRoleSet);
    LOG.debug("result = {}", result);
    return result;
  }

  @Override
  public void close() {
    providerBackend.close();
  }

  @Override
  public void validatePolicy(boolean strictValidation) throws SentryConfigurationException {
    if (providerBackend != null) {
      providerBackend.validatePolicy(strictValidation);
    }
  }
}
