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

package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.common.conf.CConfiguration;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.spi.authorization.Authorizer;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * This class implements {@link Authorizer} from CDAP and is responsible for interacting with Sentry to manage
 * privileges.
 */
public class SentryAuthorizer implements Authorizer {

  private static final Logger LOG = LoggerFactory.getLogger(SentryAuthorizer.class);
  private final AuthBinding binding;
  private final Set<Principal> superUsers;

  @Inject
  SentryAuthorizer(CConfiguration cConf) {
    final String sentrySiteUrl = cConf.get(AuthConf.SENTRY_SITE_URL);

    Preconditions.checkNotNull(sentrySiteUrl, String.format("sentry-site.xml path is null in cdap-site.xml. " +
                                                              "Please provide the path to sentry-site.xml in cdap " +
                                                              "with property name %s", AuthConf.SENTRY_SITE_URL));

    String serviceInstanceName = cConf.get(AuthConf.SERVICE_INSTANCE_NAME,
                                           AuthConf.AuthzConfVars.getDefault(AuthConf.SERVICE_INSTANCE_NAME));
    String requestorName = cConf.get(AuthConf.SERVICE_USER_NAME,
                                     AuthConf.AuthzConfVars.getDefault(AuthConf.SERVICE_USER_NAME));

    LOG.info("Configuring SentryAuthorizer with sentry-site.xml at {} requestor name {} and cdap instance name {}" +
               sentrySiteUrl, requestorName, serviceInstanceName);
    binding = new AuthBinding(sentrySiteUrl, serviceInstanceName, requestorName);
    superUsers = getSuperUsers(cConf.get(AuthConf.SUPERUSERS));
  }

  @Override
  public void grant(EntityId entityId, Principal principal, Set<Action> actions) {
    binding.grant(entityId, principal, actions);
  }


  @Override
  public void revoke(EntityId entityId, Principal principal, Set<Action> actions) {
    binding.revoke(entityId, principal, actions);
  }

  @Override
  public void revoke(EntityId entityId) {
    binding.revoke(entityId);
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Action action) throws UnauthorizedException {
    Preconditions.checkArgument(principal.getType() == Principal.PrincipalType.USER, "The given principal {} is of " +
                                  "type {}. Authorization checks can only be performed on {}.", principal,
                                principal.getType(), Principal.PrincipalType.USER);
    if (isSuperUser(principal)) {
      // superusers are allowed to perform any action on all entities so need to to authorize
      return;
    }
    boolean authorize = binding.authorize(entityId, principal, action);
    if (!authorize) {
      throw new UnauthorizedException(principal, action, entityId);
    }
  }

  private boolean isSuperUser(Principal principal) {
    return superUsers.contains(principal);
  }

  private Set<Principal> getSuperUsers(String superUsers) {
    Preconditions.checkArgument(!Strings.isNullOrEmpty(superUsers), "No superUsers found in cdap-site.xml. " +
      "Please provide a comma separated list of users who will be superusers with property name %s. " +
      "Example: user1,user2", AuthConf.SUPERUSERS);
    Set<Principal> superUsersList = new HashSet<>();
    for (String curUser : Splitter.on(",").trimResults().split(superUsers)) {
      superUsersList.add(new Principal(curUser, Principal.PrincipalType.USER));
    }
    return superUsersList;
  }
}
