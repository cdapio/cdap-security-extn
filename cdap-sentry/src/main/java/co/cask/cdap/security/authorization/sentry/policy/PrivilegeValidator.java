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

import co.cask.cdap.security.authorization.sentry.model.Authorizable;
import org.apache.sentry.policy.common.PolicyConstants;
import org.apache.sentry.policy.common.PrivilegeValidatorContext;
import org.apache.shiro.config.ConfigurationException;

/**
 * A simple PrivilegeValidator
 */
public class PrivilegeValidator implements org.apache.sentry.policy.common.PrivilegeValidator {
  @Override
  public void validate(PrivilegeValidatorContext privilegeValidatorContext) throws ConfigurationException {
    for (String section : PolicyConstants.AUTHORIZABLE_SPLITTER.split(privilegeValidatorContext.getPrivilege())) {
      if (!section.toLowerCase().startsWith(PolicyConstants.PRIVILEGE_PREFIX)) {
        Authorizable authorizable = ModelAuthorizables.from(section);
        if (authorizable == null) {
          String msg = "No authorizable found for " + section;
          throw new ConfigurationException(msg);
        }
      }
    }
  }
}
