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
 * A simple PrivilegeValidator which validates the privileges to be consistent with the order in which we expect them
 */
public class PrivilegeValidator implements org.apache.sentry.policy.common.PrivilegeValidator {

  private final ActionFactory actionFactory = new ActionFactory();

  @Override
  public void validate(PrivilegeValidatorContext context) throws ConfigurationException {

    List<String> splits = Lists.newArrayList();
    for (String section : PolicyConstants.AUTHORIZABLE_SPLITTER.split(context.getPrivilege().trim())) {
      splits.add(section);
    }

    // Check privilege splits length is at least 2 and no more than 5: the smallest and longest privilege possible with
    // action
    if (splits.size() < 2 || splits.size() > 5) {
      throw new ConfigurationException("Invalid Privilege Exception: Privilege can be given to a CDAP instance" +
                                         "or instance -> namespace or instance -> namespace (artifact|application)" +
                                         "or instance -> namespace -> (application|stream|dataset) or instance " +
                                         "-> namespace -> application -> program");
    }

    // last part should always be action so remove it to validate and also validate auth types
    String lastPart = splits.remove(splits.size() - 1);

    // Check the last part is a valid action
    if (!isAction(lastPart)) {
      throw new ConfigurationException("CDAP privilege must end with a valid action.\n");
    }

    // validate privilege string and also that it starts with instance
    validatePrivilege(splits, 0, ImmutableSet.of(Authorizable.AuthorizableType.INSTANCE));
  }

  /**
   * Recursively validates the Privilege splits.
   *
   * @param splits the privilege splits
   * @param curPosition current position which needs to be verified
   * @param validTypes the valid {@link Authorizable.AuthorizableType} for the current position
   */
  private void validatePrivilege(List<String> splits, int curPosition, Set<Authorizable.AuthorizableType> validTypes) {

    // base case: if we reach the end then break as its a valid privilege
    if (curPosition >= splits.size()) {
      return;
    }

    Authorizable authorizable = ModelAuthorizables.from(splits.get(curPosition));
    if (authorizable == null) {
      throw new ConfigurationException("No CDAP authorizable found for " + splits.get(curPosition) + "\n");
    }
    // Make sure that this authorizable type was expected after the one before
    Authorizable.AuthorizableType authzType = authorizable.getAuthzType();
    if (!validTypes.contains(authzType)) {
      throw new ConfigurationException("Expecting authorizable types " + validTypes.toString() + "after " + splits
        .get(curPosition - 1) + "but found " + authzType);
    }
    switch (authzType) {
      case INSTANCE:
        // instance can be followed namespace
        validatePrivilege(splits, curPosition + 1, ImmutableSet.of(Authorizable.AuthorizableType.NAMESPACE));
        break;
      case NAMESPACE:
        // namespace can be followed by application, artifact, stream or dataset
        validatePrivilege(splits, curPosition + 1, ImmutableSet.of(Authorizable.AuthorizableType.APPLICATION,
                                                                   Authorizable.AuthorizableType.ARTIFACT,
                                                                   Authorizable.AuthorizableType.STREAM,
                                                                   Authorizable.AuthorizableType.DATASET));
        break;
      case APPLICATION:
        // application can be followed by program
        validatePrivilege(splits, curPosition + 1, ImmutableSet.of(Authorizable.AuthorizableType.PROGRAM));
        break;
      // these are terminating authorization types i.e. we don't expect any other authorizable type following them
      case ARTIFACT:
      case STREAM:
      case DATASET:
      case PROGRAM:
        // this should be the last authz type
        if (splits.size() - 1 != curPosition) {
          throw new ConfigurationException(String.format("Authorizable type %s should be the last Authorizable type",
                                                         splits.get(curPosition)));
        }
    }
  }

  private boolean isAction(String privilegePart) {
    final String privilege = privilegePart.toLowerCase();
    final String[] action = privilege.split(PolicyConstants.KV_SEPARATOR);
    return (action.length == 2 && action[0].equalsIgnoreCase(PolicyConstants.PRIVILEGE_NAME) &&
      actionFactory.getActionByName(action[1]) != null);
  }
}
