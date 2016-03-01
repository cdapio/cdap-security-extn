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

package co.cask.cdap.security.authorization.sentry.policy;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.apache.sentry.core.common.ActiveRoleSet;
import org.apache.sentry.core.common.Authorizable;
import org.apache.sentry.core.common.SentryConfigurationException;
import org.apache.sentry.policy.common.PolicyEngine;
import org.apache.sentry.policy.common.PrivilegeFactory;
import org.apache.sentry.provider.common.ProviderBackend;
import org.apache.sentry.provider.common.ProviderBackendContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * Created by rsinha on 2/29/16.
 */
public class SimplePolicyEngine implements PolicyEngine {
  private static final Logger LOGGER = LoggerFactory.getLogger(SimplePolicyEngine.class);
  private final ProviderBackend providerBackend;

  public SimplePolicyEngine(ProviderBackend providerBackend) {
    this.providerBackend = providerBackend;
    ProviderBackendContext context = new ProviderBackendContext();
    context.setAllowPerDatabase(false);
    context.setValidators(ImmutableList.<org.apache.sentry.policy.common.PrivilegeValidator>of(
      new PrivilegeValidator()));
    this.providerBackend.initialize(context);
  }

  @Override
  public PrivilegeFactory getPrivilegeFactory() {
    return new WildcardPrivilege.Factory();
  }

  @Override
  public ImmutableSet<String> getAllPrivileges(Set<String> set,
                                               ActiveRoleSet activeRoleSet) throws SentryConfigurationException {
    return getPrivileges(set, activeRoleSet);
  }

  @Override
  public ImmutableSet<String> getPrivileges(Set<String> set, ActiveRoleSet activeRoleSet,
                                            Authorizable... authorizables) throws SentryConfigurationException {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Getting permissions for {}", set);
    }
    ImmutableSet<String> result = providerBackend.getPrivileges(set, activeRoleSet);
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("result = " + result);
    }
    return result;
  }

  @Override
  public void close() {
    if (providerBackend != null) {
      providerBackend.close();
    }
  }

  @Override
  public void validatePolicy(boolean strictValidation) throws SentryConfigurationException {
    if (providerBackend != null) {
      providerBackend.validatePolicy(strictValidation);
    }
  }
}
