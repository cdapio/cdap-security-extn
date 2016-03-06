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

import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Created by rsinha on 2/29/16.
 */
public class AuthBindingSingleton {
  private static Logger log = LoggerFactory.getLogger(AuthBindingSingleton.class);

  // Lazy init holder class idiom to avoid DCL
  private static class AuthBindingSingletonHolder {
    static final AuthBindingSingleton INSTANCE = new AuthBindingSingleton();
  }

  private static AuthConf authConf = null;

  private AuthBinding binding;

  private AuthBindingSingleton() {
  }

  private AuthConf loadAuthzConf(String sentrySite) {
    if (Strings.isNullOrEmpty(sentrySite)) {
      throw new IllegalArgumentException("Configuration key " + AuthConf.SENTRY_SITE_URL
                                           + " value '" + sentrySite + "' is invalid.");
    }

    AuthConf authConf;
    try {
      authConf = new AuthConf(new URL(sentrySite));
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Configuration key " + AuthConf.SENTRY_SITE_URL
                                           + " specifies a malformed URL '" + sentrySite + "'", e);
    }
    return authConf;
  }

  public void configure(String instanceName, String requestorName, String sentrySite) {
    try {
      authConf = loadAuthzConf(sentrySite);
      binding = new AuthBinding(authConf, instanceName, requestorName);
      log.info("AuthBinding created successfully");
    } catch (Exception ex) {
      throw new RuntimeException("Unable to create AuthBinding: " + ex.getMessage(), ex);
    }
  }

  public static AuthBindingSingleton getInstance() {
    return AuthBindingSingletonHolder.INSTANCE;
  }

  public AuthBinding getAuthBinding() {
    if (binding == null) {
      throw new RuntimeException("AuthBindingSingleton not configured yet.");
    }
    return binding;
  }

  public AuthConf getAuthConf() {
    if (binding == null) {
      throw new RuntimeException("AuthBindingSingleton not configured yet.");
    }
    return authConf;
  }
}

