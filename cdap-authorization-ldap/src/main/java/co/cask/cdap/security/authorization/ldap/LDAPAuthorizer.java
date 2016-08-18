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

package co.cask.cdap.security.authorization.ldap;

import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.InstanceId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.NamespacedId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.Authorizer;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
 * An implementation of {@link Authorizer} using LDAP as the backing store.
 */
public class LDAPAuthorizer extends AbstractAuthorizer {

  private static final Logger LOG = LoggerFactory.getLogger(LDAPAuthorizer.class);

  private static final String VERIFY_SSL_CERT_PROPERTY = "sslVerifyCertificate";
  private static final String CREDENTIALS_KEY_NAME = "credentialsKeyName";

  private static final String USER_BASE_DN = "userBaseDn";
  private static final String USER_RDN_ATTRIBUTE = "userRdnAttribute";
  private static final String SEARCH_RECURSIVE = "searchRecursive";

  private DirContext dirContext;
  private SearchConfig instanceSearchConfig;
  private SearchConfig namespaceSearchConfig;
  private String userBaseDn;
  private String userRdnAttribute;
  private boolean searchRecursive;
  private Principal systemPrincipal;

  @Override
  public void initialize(AuthorizationContext context) throws Exception {
    super.initialize(context);
    Properties properties = context.getExtensionProperties();

    String providerUrl = properties.getProperty(Context.PROVIDER_URL);
    if (providerUrl == null) {
      throw new IllegalArgumentException("Missing provider url configuration '" + Context.PROVIDER_URL + "'");
    }
    if (!providerUrl.startsWith("ldap://") && !providerUrl.startsWith("ldaps://")) {
      throw new IllegalArgumentException("Unsupported provider '" + providerUrl + "'. Only LDAP is supported.");
    }

    instanceSearchConfig = createSearchConfig(properties, "instance");
    namespaceSearchConfig = createSearchConfig(properties, "namespace");

    userBaseDn = checkAndGet(properties, USER_BASE_DN);
    userRdnAttribute = checkAndGet(properties, USER_RDN_ATTRIBUTE);

    Hashtable<String, Object> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    for (String key : properties.stringPropertyNames()) {
      env.put(key, properties.getProperty(key));
    }

    boolean useSSL = "ssl".equals(properties.getProperty(Context.SECURITY_PROTOCOL))
      || providerUrl.startsWith("ldaps://");

    if (useSSL && !Boolean.parseBoolean(properties.getProperty(VERIFY_SSL_CERT_PROPERTY))) {
      env.put("java.naming.ldap.factory.socket", TrustAllSSLSocketFactory.class.getName());
    }

    // Retrieves the actual LDAP credentials from secure store if needed
    String credentialsKeyName = properties.getProperty(CREDENTIALS_KEY_NAME);
    if (credentialsKeyName != null) {
      int idx = credentialsKeyName.indexOf(':');
      if (idx < 0) {
        throw new IllegalArgumentException("The '" + CREDENTIALS_KEY_NAME +
                                             "' property must be in the form 'namespace:keyname'");
      }

      env.put(Context.SECURITY_CREDENTIALS,
              context.getSecureData(credentialsKeyName.substring(0, idx), credentialsKeyName.substring(idx + 1)));
    }

    dirContext = new InitialDirContext(env);
    searchRecursive = Boolean.getBoolean(SEARCH_RECURSIVE);

    systemPrincipal = new Principal(UserGroupInformation.getCurrentUser().getShortUserName(),
                                    Principal.PrincipalType.USER);
    LOG.info("Initialized {} with properties {}. System user is {}.",
             LDAPAuthorizer.class.getSimpleName(), properties, systemPrincipal);
  }

  @Override
  public void destroy() throws Exception {
    dirContext.close();
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    String filter = "(&({0}={1})(objectClass={2})({3}={4}))";
    SearchConfig searchConfig;
    String entityName;

    // Special case for system user that it can always access system namespace
    if (systemPrincipal.equals(principal) && NamespaceId.SYSTEM.equals(entityId)) {
      return;
    }

    // Based on the requested EntityId, use different search config
    if (entityId instanceof InstanceId) {
      // Query for membership of the given principal in the instance
      searchConfig = instanceSearchConfig;
      entityName = ((InstanceId) entityId).getInstance();
    } else if (entityId instanceof NamespacedId) {

      // Query for the membership of the given principal in the namespace
      searchConfig = namespaceSearchConfig;
      entityName = ((NamespacedId) entityId).getNamespace();
    } else {
      throw new IllegalArgumentException("Unsupported entity type '" + entityId.getClass() +
                                           "' of entity '" + entityId + "'.");
    }

    // Search for the user group membership
    Object[] filterArgs = new Object[] {
      searchConfig.getNameAttribute(), entityName,
      searchConfig.getObjectClass(), searchConfig.getMemberAttribute(),
      String.format("%s=%s,%s", userRdnAttribute, principal.getName(), userBaseDn)
    };

    SearchControls searchControls = new SearchControls();
    searchControls.setDerefLinkFlag(true);
    if (searchRecursive) {
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }

    NamingEnumeration<SearchResult> results = dirContext.search(searchConfig.getBaseDn(),
                                                                filter, filterArgs, searchControls);
    try {
      if (!results.hasMore()) {
        throw new UnauthorizedException(principal, actions, entityId);
      }
    } finally {
      results.close();
    }

    // Currently assumes membership in a namespace allows full access, hence not checking actions
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    Set<Privilege> privileges = new LinkedHashSet<>();

    String filter = "(&(objectClass={0})({1}={2}))";

    // Query for all instances and namespaces that the given principal is a member of
    for (SearchConfig searchConfig : Arrays.asList(instanceSearchConfig, namespaceSearchConfig)) {
      Object[] filterArgs = new Object[] {
        searchConfig.getObjectClass(), searchConfig.getMemberAttribute(),
        String.format("%s=%s,%s", userRdnAttribute, principal.getName(), userBaseDn)
      };
      SearchControls searchControls = new SearchControls();
      searchControls.setDerefLinkFlag(true);
      searchControls.setReturningAttributes(new String[] { searchConfig.getNameAttribute() });
      if (searchRecursive) {
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
      }
      NamingEnumeration<SearchResult> results = dirContext.search(searchConfig.getBaseDn(),
                                                                  filter, filterArgs, searchControls);
      try {
        // When a user is in a given group, then he is allowed to perform all action in that group
        while (results.hasMore()) {
          SearchResult result = results.next();
          Attribute attribute = result.getAttributes().get(searchConfig.getNameAttribute());
          if (attribute != null) {
            String entityName = attribute.get().toString();
            for (Action action : Action.values()) {
              privileges.add(new Privilege(createEntity(searchConfig, entityName), action));
            }
          }
        }
      } finally {
        results.close();
      }
    }

    // Special case for system user that it can always access system namespace
    if (systemPrincipal.equals(principal)) {
      for (Action action: Action.values()) {
        privileges.add(new Privilege(NamespaceId.SYSTEM, action));
      }
    }

    return privileges;
  }

  @Override
  public void createRole(Role role) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("createRole not support");
  }

  @Override
  public void dropRole(Role role) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("dropRole not support");
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("addRoleToPrincipal not support");
  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("removeRoleFromPrincipal not support");
  }

  @Override
  public Set<Role> listRoles(Principal principal) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("listRoles not support");
    return Collections.emptySet();
  }

  @Override
  public Set<Role> listAllRoles() throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("listRoles not support");
    return Collections.emptySet();
  }

  @Override
  public void grant(EntityId entityId, Principal principal, Set<Action> set) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("grant not support");
  }

  @Override
  public void revoke(EntityId entityId, Principal principal, Set<Action> set) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("revoke not support");
  }

  @Override
  public void revoke(EntityId entityId) throws Exception {
    // Can't throw exception because it will fail CDAP deployment operation
    LOG.debug("revoke not support");
  }

  private String checkAndGet(Properties properties, String key) {
    String value = properties.getProperty(key);
    if (value == null) {
      throw new IllegalArgumentException("Property '" + key + "' is missing");
    }
    return value;
  }

  private SearchConfig createSearchConfig(Properties properties, String keyPrefix) {
    String baseDn = checkAndGet(properties, keyPrefix + "BaseDn");
    String objectClass = checkAndGet(properties, keyPrefix + "ObjectClass");
    String memberAttribute = checkAndGet(properties, keyPrefix + "MemberAttribute");
    String nameAttribute = checkAndGet(properties, keyPrefix + "NameAttribute");

    return new SearchConfig(baseDn, objectClass, memberAttribute, nameAttribute);
  }

  private EntityId createEntity(SearchConfig searchConfig, String id) {
    if (searchConfig == instanceSearchConfig) {
      return new InstanceId(id);
    } else if (searchConfig == namespaceSearchConfig) {
      return new NamespaceId(id);
    }
    // Shouldn't happen
    throw new IllegalArgumentException("Unknown SearchConfig: " + searchConfig);
  }
}
