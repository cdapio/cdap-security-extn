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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
  private static final String NAMESPACE_BASE_DN = "namespaceBaseDn";
  private static final String NAMESPACE_OBJECT_CLASS = "namespaceObjectClass";
  private static final String NAMESPACE_MEMBER_ATTRIBUTE = "namespaceMemberAttribute";
  private static final String NAMESPACE_NAME_ATTRIBUTE = "namespaceNameAttribute";
  private static final String SEARCH_RECURSIVE = "searchRecursive";

  private DirContext dirContext;
  private String userBaseDn;
  private String userRdnAttribute;
  private String namespaceBaseDn;
  private String namespaceObjectClass;
  private String namespaceMemberAttribute;
  private String namespaceNameAttribute;
  private boolean searchRecursive;

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

    userBaseDn = checkAndGet(properties, USER_BASE_DN);
    userRdnAttribute = checkAndGet(properties, USER_RDN_ATTRIBUTE);
    namespaceBaseDn = checkAndGet(properties, NAMESPACE_BASE_DN);
    namespaceObjectClass = checkAndGet(properties, NAMESPACE_OBJECT_CLASS);
    namespaceMemberAttribute = checkAndGet(properties, NAMESPACE_MEMBER_ATTRIBUTE);
    namespaceNameAttribute = checkAndGet(properties, NAMESPACE_NAME_ATTRIBUTE);

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

    LOG.info("Initialized {} with properties {}", LDAPAuthorizer.class.getSimpleName(), properties);
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    if (!(entityId instanceof NamespacedId)) {
      throw new IllegalArgumentException("Unsupported entity type '" + entityId.getClass() +
                                           "' of entity '" + entityId + "'. Only entity with namespace is supported.");
    }

    // Query for the membership of the given principal in the namespace
    String filter = "(&({0}={1})(objectClass={2})({3}={4}))";
    Object[] filterArgs = new Object[] {
      namespaceNameAttribute, ((NamespacedId) entityId).getNamespace(),
      namespaceObjectClass, namespaceMemberAttribute,
      String.format("%s=%s,%s", userRdnAttribute, principal.getName(), userBaseDn)
    };

    SearchControls searchControls = new SearchControls();
    searchControls.setDerefLinkFlag(true);
    if (searchRecursive) {
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }

    NamingEnumeration<SearchResult> results = dirContext.search(namespaceBaseDn, filter, filterArgs, searchControls);
    if (!results.hasMore()) {
      throw new UnauthorizedException(principal, actions, entityId);
    }

    // Currently assumes membership in a namespace allows full access, hence not checking actions
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    // Query for all namespaces that the given principal is a member of
    String filter = "(&(objectClass={0})({1}={2}))";
    Object[] filterArgs = new Object[] {
      namespaceObjectClass, namespaceMemberAttribute,
      String.format("%s=%s,%s", userRdnAttribute, principal.getName(), userBaseDn)
    };

    SearchControls searchControls = new SearchControls();
    searchControls.setDerefLinkFlag(true);
    searchControls.setReturningAttributes(new String[] { namespaceNameAttribute });
    if (searchRecursive) {
      searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    }

    Set<Privilege> privileges = new LinkedHashSet<>();
    NamingEnumeration<SearchResult> results = dirContext.search(namespaceBaseDn, filter, filterArgs, searchControls);

    // When a user is in a given namespace, then he is allowed to perform all action in that namespace
    while (results.hasMore()) {
      SearchResult result = results.next();
      Attribute attribute = result.getAttributes().get(namespaceNameAttribute);
      if (attribute != null) {
        for (Action action : Action.values()) {
          privileges.add(new Privilege(new NamespaceId(attribute.get().toString()), action));
        }
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
}
