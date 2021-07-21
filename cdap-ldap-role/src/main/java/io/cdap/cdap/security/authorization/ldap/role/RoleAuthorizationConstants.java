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

package io.cdap.cdap.security.authorization.ldap.role;

/**
 * Constants for {@link LDAPRoleAccessController} class
 */
public final class RoleAuthorizationConstants {
  /**
   * Name of system namespace
   */
  public static final String SYSTEM_NAMESPACE = "system";

  /**
   * Constants to get information about extension from manifest
   */
  public static final String MANIFEST_PATH = "META-INF/MANIFEST.MF";
  public static final String MANIFEST_TITLE_NAME = "Specification-Title";
  public static final String MANIFEST_VERSION_NAME = "Specification-Version";
  public static final String MANIFEST_BUILD_TIME_NAME = "Build-Time";
  public static final String MANIFEST_BUILD_COMMIT_HASH_NAME = "Build-Commit-Hash";

  /**
   * Username for ldap connection from SecureStore, overrides deployment (example "CN=root,CN=Users,DC=test,DC=local").
   */
  public static final String LDAP_BIND_DN = "ldap_bind_dn";
  /**
   * Password for ldap connection from SecureStore, overrides deployment.
   */
  public static final String LDAP_BIND_PASS = "ldap_bind_pass";

  /**
   * Url for connecting ldap (example "ldap://10.10.10.10:389/").
   */
  public static final String LDAP_URL = "ldap.url";
  /**
   * Filter for searching (example "(&(objectClass=person)(samaccountname=%s))").
   */
  public static final String LDAP_SEARCH_FILTER = "ldap.search.filter";
  /**
   * DN for searching, can be separated with ';' (example "DC=test1,DC=local;DC=test2,DC=local").
   */
  public static final String LDAP_SEARCH_BASE_DN = "ldap.search.base.dn";
  /**
   * Member attribute for searching groups (example “memberOf”).
   */
  public static final String LDAP_MEMBER_ATTRIBUTE = "ldap.member.attribute";
  /**
   * Username for ldap connection (example "CN=root,CN=Users,DC=test,DC=local").
   */
  public static final String LDAP_LOOKUP_BIND_DN = "ldap.lookup.bind.dn";
  /**
   * Password for ldap connection.
   */
  public static final String LDAP_LOOKUP_BIND_PASSWORD = "ldap.lookup.bind.password";
  /**
   * Use recursive search or not (example "true").
   */
  public static final String LDAP_RECURSIVE_SEARCH = "ldap.recursive.search";
  /**
   * Skip LDAP ssl certificates verification or not (example “false”).
   */
  public static final String LDAP_IGNORE_SSL_VERIFY = "ldap.ignore.ssl.verify";

  /**
   * Properties for ldap pool configuration, more information can be found
   * <a href="https://docs.oracle.com/javase/jndi/tutorial/ldap/connect/config.html">here</a>.
   */
  public static final String LDAP_POOL_AUTHENTICATION = "ldap.pool.authentication";
  public static final String LDAP_POOL_DEBUG = "ldap.pool.debug";
  public static final String LDAP_POOL_INITSIZE = "ldap.pool.initsize";
  public static final String LDAP_POOL_MAXSIZE = "ldap.pool.maxsize";
  public static final String LDAP_POOL_PREFSIZE = "ldap.pool.prefsize";
  public static final String LDAP_POOL_PROTOCOL = "ldap.pool.protocol";
  public static final String LDAP_POOL_TIMEOUT = "ldap.pool.timeout";

  /**
   * Path to yaml with role mappings (example "/data/roles.yaml").
   */
  public static final String ROLE_YAML_PATH = "role.yaml.path";

  /**
   * Disable plugin and only log requests, can be used for debug.
   */
  public static final String LOGGING_ONLY = "logging.only";

  /**
   * Ignoring of users, specified as 'fullAccessUsers' in yaml with role mappings.
   * If enabled, then extension will ignore these users, and they will have full access.
   * Was added as workaround for embedded CDAP users.
   */
  public static final String IGNORE_FULL_ACCESS_USERS = "ignore.full.access.users";

  /**
   * Disable or not feature with permissions propagation.
   * With permissions propagation feature, if permission is not set in any of the configured roles, then system will
   * try to find similar permissions for the current namespace.
   * The only exception is system namespace, compute profile and secure key entities.
   * For example if a user has GET permissions in namespace, he will also GET other objects in this namespace.
   */
  public static final String DISABLE_PERMISSIONS_PROPAGATION = "disable.permissions.propagation";
}
