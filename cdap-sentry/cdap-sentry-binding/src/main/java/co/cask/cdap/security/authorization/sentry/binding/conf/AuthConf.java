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

package co.cask.cdap.security.authorization.sentry.binding.conf;

import co.cask.cdap.security.authorization.sentry.policy.SimplePolicyEngine;
import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.provider.common.HadoopGroupResourceAuthorizationProvider;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;

import java.net.URL;
import javax.annotation.Nullable;

/**
 * Authorization Configurations used for Sentry binding
 */
public class AuthConf extends Configuration {

  // sentry-site.xml path
  public static final String SENTRY_SITE_URL = "security.sentry.site.url";
  // sentry site filename
  public static final String SENTRY_SITE_FILENAME = "sentry-site.xml";
  // cdap instance name to be used in sentry for example: cdap
  public static final String SERVICE_INSTANCE_NAME = "security.cdap.instance.name";
  // cdap username to be used in sentry for example: cdap
  public static final String SERVICE_USER_NAME = "security.cdap.user.name";
  // a comma separated list of users who will be superusers
  public static final String SERVICE_SUPERUSERS = "sentry.cdap.superusers";

  /**
   * Config setting definitions
   */
  public enum AuthzConfVars {
    AUTHZ_PROVIDER("sentry.cdap.provider", HadoopGroupResourceAuthorizationProvider.class.getName()),
    AUTHZ_PROVIDER_BACKEND("sentry.cdap.provider.backend", SentryGenericProviderBackend.class.getName()),
    AUTHZ_POLICY_ENGINE("sentry.cdap.policy.engine", SimplePolicyEngine.class.getName()),
    AUTHZ_PROVIDER_RESOURCE("sentry.cdap.provider.resource", ""),
    // if no instanceName or username is provided 'cdap' will be used
    AUTHZ_SERVICE_INSTANCE_NAME(SERVICE_INSTANCE_NAME, "cdap"),
    AUTHZ_SERVICE_USER_NAME(SERVICE_USER_NAME, "cdap"),
    AUTHZ_SERVICE_SUPERUSERS(SERVICE_SUPERUSERS, "");

    private final String varName;
    private final String defaultVal;

    AuthzConfVars(String varName, String defaultVal) {
      this.varName = varName;
      this.defaultVal = defaultVal;
    }

    public String getVar() {
      return varName;
    }

    public String getDefault() {
      return defaultVal;
    }

    @Nullable
    public static String getDefault(String varName) {
      for (AuthzConfVars oneVar : AuthzConfVars.values()) {
        if (oneVar.getVar().equalsIgnoreCase(varName)) {
          return oneVar.getDefault();
        }
      }
      // do not throw exception as the configuration expects null of not present
      return null;
    }
  }

  public AuthConf(URL sentrySiteURL) {
    super(true);
    addResource(sentrySiteURL);
  }

  @Override
  public String get(String varName) {
    return get(varName, AuthzConfVars.getDefault(varName));
  }
}
