/*
 * Copyright © 2021-2022 Cask Data, Inc.
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

package io.cdap.cdap.security.authorization.ldap.role.searcher;

/**
 * Constants for {@link LDAPSearcher} class
 */
public class LDAPConstants {
  public static final String LDAP_SOCKET_FACTORY = "java.naming.ldap.factory.socket";
  public static final String LDAP_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
  public static final String LDAPS_PROTOCOL = "ldaps";
  public static final String BASE_DN_SPLITTER = ";";

  // Retry config values
  public static final int MAX_CONNECTION_RETRIES = 5;
  public static final int MAX_SEARCH_RETRIES = 2;
  public static final long DEFAULT_RETRY_INTERVAL = 1000;

  // LDAP pool properties names
  public static final String LDAP_POOL = "com.sun.jndi.ldap.connect.pool";
  public static final String LDAP_POOL_AUTHENTICATION = "com.sun.jndi.ldap.connect.pool.authentication";
  public static final String LDAP_POOL_DEBUG = "pool.debug";
  public static final String LDAP_POOL_INITSIZE = "pool.initsize";
  public static final String LDAP_POOL_MAXSIZE = "pool.maxsize";
  public static final String LDAP_POOL_PREFSIZE = "pool.prefsize";
  public static final String LDAP_POOL_PROTOCOL = "pool.protocol";
  public static final String LDAP_POOL_TIMEOUT = "pool.timeout";
}
