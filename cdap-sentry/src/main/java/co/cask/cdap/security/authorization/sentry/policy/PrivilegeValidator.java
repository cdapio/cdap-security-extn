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

import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import co.cask.cdap.security.authorization.sentry.model.Authorizable;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import org.apache.sentry.policy.common.PolicyConstants;
import org.apache.sentry.policy.common.PrivilegeValidatorContext;
import org.apache.shiro.config.ConfigurationException;

import java.util.List;
import java.util.Set;

/**
 * A simple PrivilegeValidator
 */
public class PrivilegeValidator implements org.apache.sentry.policy.common.PrivilegeValidator {
  @Override
  public void validate(PrivilegeValidatorContext context) throws ConfigurationException {
    List<String> splits = Lists.newArrayList();
    for (String section : PolicyConstants.AUTHORIZABLE_SPLITTER.split(context.getPrivilege())) {
      splits.add(section);
    }

    // Check privilege splits length is 2 or 3
    if (splits.size() < 2 || splits.size() > 5) {
      throw new ConfigurationException("Invalid Privilege Exception: Privilege can be given to a CDAP instance" +
                                         "or instance -> namespace or instance -> namespace (artifact|application)" +
                                         "or instance -> namespace -> (application|stream|dataset) or instance " +
                                         "-> namespace -> application -> program");
    }

    // remove the action and validate auth types
    String lastPart = splits.remove(splits.size() - 1);

    // Check the last part is a valid action
    if (!isAction(lastPart)) {
      throw new ConfigurationException("CDAP privilege must end with a valid action.\n");
    }

    // validate privilege string and also that it starts with instance
    validatePrivilege(splits, 0, ImmutableSet.of(Authorizable.AuthorizableType.INSTANCE));
  }

  private void validatePrivilege(List<String> splits, int curPosition, Set<Authorizable.AuthorizableType> validTypes) {

    // if we reach the end then break as its a valid privilege
    if (curPosition >= splits.size()) {
      return;
    }

    Authorizable authorizable = ModelAuthorizables.from(splits.get(curPosition));
    if (authorizable == null) {
      throw new ConfigurationException("No CDAP authorizable found for " + splits.get(curPosition) + "\n");
    }
    Authorizable.AuthorizableType authzType = authorizable.getAuthzType();
    if (!validTypes.contains(authzType)) {
      throw new ConfigurationException("not valid auth");
    }
    switch (authzType) {
      case INSTANCE:
        // instance can be followed namespace
        validatePrivilege(splits, curPosition + 1, ImmutableSet.of(Authorizable.AuthorizableType.NAMESPACE));
        break;
      case NAMESPACE:
        // namespace can be followed by application or artifact
        validatePrivilege(splits, curPosition + 1, ImmutableSet.of(Authorizable.AuthorizableType.APPLICATION,
                                                                   Authorizable.AuthorizableType.ARTIFACT,
                                                                   Authorizable.AuthorizableType.STREAM,
                                                                   Authorizable.AuthorizableType.DATASET));
        break;
      case APPLICATION:
        // application can be followed by program
        validatePrivilege(splits, curPosition + 1, ImmutableSet.of(Authorizable.AuthorizableType.PROGRAM));
        break;
      case ARTIFACT:
      case STREAM:
      case DATASET:
      case PROGRAM:
    }
  }

  private boolean isAction(String privilegePart) {
    final String privilege = privilegePart.toLowerCase();
    final String[] action = privilege.split(PolicyConstants.KV_SEPARATOR);
    return (action.length == 2 && action[0].equalsIgnoreCase(PolicyConstants.PRIVILEGE_NAME) &&
      ActionFactory.getInstance().getActionByName(action[1]) != null);
  }
}
