/*
 * Copyright © 2017 Cask Data, Inc.
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
package co.cask.cdap.security.authorization.ranger.lookup.client;

import com.google.common.base.Strings;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * CDAP Client and Connection Manager.
 */
public class CDAPConnectionManager {

  private static final String INSTANCE_URL = "cdap.instance.url";
  private static final String USERNAME = "cdap.username";
  private static final String PASSWORD = "cdap.password";

  /**
   * Returns a CDAP Client containing namespace, stream, dataset etc clients
   *
   * @param serviceName the name of the service e.g. cdap
   * @param configs configs to use to create the cdap clients.
   * @return {@link CDAPRangerLookupClient}
   */
  public static CDAPRangerLookupClient getCDAPClient(String serviceName, Map<String, String> configs)
    throws IOException, TimeoutException, InterruptedException {
    String instanceURL = configs.get(INSTANCE_URL);
    String username = configs.get(USERNAME);
    String password = configs.get(PASSWORD);
    if (!(Strings.isNullOrEmpty(instanceURL) || Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password))) {
      return new CDAPRangerLookupClient(instanceURL, username, password);
    }
    throw new IllegalArgumentException("Required properties are not set for "
                          + serviceName + ". CDAP instance url with port, username and password must be provided.");
  }

  /**
   * Tests that connection to CDAP instance can be made with the given config
   *
   * @param serviceName the name of the service
   * @param configs the configs for the connection
   * @return Map&lt;String, Object&gt; Connection test response
   */
  public static Map<String, Object> testConnection(String serviceName, Map<String, String> configs) throws Exception {
    CDAPRangerLookupClient cdapRangerLookupClient = getCDAPClient(serviceName, configs);
    return cdapRangerLookupClient.testConnection();
  }
}
