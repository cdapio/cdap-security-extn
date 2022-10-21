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

import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.id.NamespacedEntityId;
import io.cdap.cdap.proto.security.Permission;
import io.cdap.cdap.security.authorization.ldap.role.group.GroupWithRolesProvider;
import io.cdap.cdap.security.authorization.ldap.role.group.PrincipalPermissions;
import io.cdap.cdap.security.authorization.ldap.role.permission.RolePermissionConverter;
import io.cdap.cdap.security.authorization.ldap.role.searcher.LDAPSearchConfig;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

/**
 * Utils for {@link LDAPRoleAccessController} class
 */
public class RoleAuthorizationUtil {
  private static final List<EntityType> SECURED_ENTITY_TYPES = Arrays.asList(
    EntityType.SECUREKEY, // Properties with secured information
    EntityType.PROFILE // Allows getting SSH key for Profile
  );

  /**
   * Gets flag for ignoring full access users from configuration
   *
   * @param properties {@link Properties} set for extension
   * @return if users with full access should be ignored
   */
  public static boolean getIgnoreFullAccessUsersValue(Properties properties) {
    String ignoreFullAccessUsersString = properties.getProperty(RoleAuthorizationConstants.IGNORE_FULL_ACCESS_USERS);
    return Boolean.parseBoolean(ignoreFullAccessUsersString);
  }

  /**
   * Gets flag for disabling extension and only logging from configuration
   *
   * @param properties {@link Properties} set for extension
   * @return if extension should be disabled
   */
  public static boolean getLoggingOnlyValue(Properties properties) {
    String ignoreSystemUserString = properties.getProperty(RoleAuthorizationConstants.LOGGING_ONLY);
    return Boolean.parseBoolean(ignoreSystemUserString);
  }

  /**
   * Gets flag for disabling permissions propagation
   *
   * @param properties {@link Properties} set for extension
   * @return if permissions propagation should be disabled
   */
  public static boolean getDisablePermissionsPropagationValue(Properties properties) {
    String disablePermissionsPropagationString = properties.getProperty(RoleAuthorizationConstants
                                                                          .DISABLE_PERMISSIONS_PROPAGATION);
    return Boolean.parseBoolean(disablePermissionsPropagationString);
  }

  /**
   * Creates provider of groups and roles from extension configuration
   *
   * @param properties {@link Properties} set for extension
   * @return {@link GroupWithRolesProvider}
   */
  public static GroupWithRolesProvider createLDAPGroupRoleProvider(Properties properties) {
    String yamlPath = getProperty(RoleAuthorizationConstants.ROLE_YAML_PATH, properties);
    return new GroupWithRolesProvider(yamlPath);
  }

  /**
   * Creates config for LDAP searcher from extension configuration
   *
   * @param properties {@link Properties} set for extension
   * @return {@link LDAPSearchConfig} for LDAP searcher
   */
  public static LDAPSearchConfig createSearchConfig(Properties properties) {
    String ignoreSSLVerifyString = properties.getProperty(RoleAuthorizationConstants.LDAP_IGNORE_SSL_VERIFY);
    String recursiveSearchString = properties.getProperty(RoleAuthorizationConstants.LDAP_RECURSIVE_SEARCH);

    return LDAPSearchConfig.builder()
      .withUrl(getProperty(RoleAuthorizationConstants.LDAP_URL, properties))
      .withSearchBaseDn(getProperty(RoleAuthorizationConstants.LDAP_SEARCH_BASE_DN, properties))
      .withSearchFilter(getProperty(RoleAuthorizationConstants.LDAP_SEARCH_FILTER, properties))
      .withMemberAttribute(properties.getProperty((RoleAuthorizationConstants.LDAP_MEMBER_ATTRIBUTE)))
      .withLookUpBindDN(properties.getProperty(RoleAuthorizationConstants.LDAP_LOOKUP_BIND_DN))
      .withLookUpBindPassword(properties.getProperty(RoleAuthorizationConstants.LDAP_LOOKUP_BIND_PASSWORD))
      .withIgnoreSSLVerify(Boolean.parseBoolean(ignoreSSLVerifyString))
      .withRecursiveSearch(Boolean.parseBoolean(recursiveSearchString))
      .withPoolAuthentication(properties.getProperty(RoleAuthorizationConstants.LDAP_POOL_AUTHENTICATION))
      .withPoolDebug(properties.getProperty(RoleAuthorizationConstants.LDAP_POOL_DEBUG))
      .withPoolInitsize(properties.getProperty(RoleAuthorizationConstants.LDAP_POOL_INITSIZE))
      .withPoolMaxsize(properties.getProperty(RoleAuthorizationConstants.LDAP_POOL_MAXSIZE))
      .withPoolPrefsize(properties.getProperty(RoleAuthorizationConstants.LDAP_POOL_PREFSIZE))
      .withPoolProtocol(properties.getProperty(RoleAuthorizationConstants.LDAP_POOL_PROTOCOL))
      .withPoolTimeout(properties.getProperty(RoleAuthorizationConstants.LDAP_POOL_TIMEOUT))
      .build();
  }

  /**
   * Return optional of propagated {@link Permission}
   *
   * @param entityId             {@link EntityId}
   * @param permission           {@link Permission}
   * @param principalPermissions {@link PrincipalPermissions}
   * @return Optional of propagated {@link Permission}
   */
  public static Optional<? extends Permission> getPropagatedPermission(EntityId entityId,
                                                                       Permission permission,
                                                                       PrincipalPermissions principalPermissions) {
    return getPropagatedPermissions(entityId, Collections.singleton(permission), principalPermissions)
      .stream()
      .findAny();
  }

  /**
   * Returns set of propagated {@link Permission}
   *
   * @param entityId             {@link EntityId}
   * @param permissions          Set of {@link Permission}
   * @param principalPermissions {@link PrincipalPermissions}
   * @return Set of propagated {@link Permission}
   */
  public static Set<? extends Permission> getPropagatedPermissions(EntityId entityId,
                                                                   Set<? extends Permission> permissions,
                                                                   PrincipalPermissions principalPermissions) {
    String namespace = RolePermissionConverter.SYSTEM_NAMESPACE;
    // If EntityId has namespace attributes, otherwise checking in system namespace
    if (entityId instanceof NamespacedEntityId) {
      namespace = ((NamespacedEntityId) entityId).getNamespace();
    }

    EntityType entityType = entityId.getEntityType();
    // Ignoring if entity is in system namespace or secure sensitive
    if (namespace.equals(RolePermissionConverter.SYSTEM_NAMESPACE) || SECURED_ENTITY_TYPES.contains(entityType)) {
      return Collections.emptySet();
    }

    return principalPermissions.getPermissions(namespace, EntityType.NAMESPACE, permissions);
  }

  /**
   * Returns property's value
   *
   * @param propertyName {@link EntityId}
   * @param properties   Set of {@link Permission}
   * @return property's value
   * @throws RuntimeException - if property is empty or not set
   */
  public static String getProperty(String propertyName, Properties properties) throws RuntimeException {
    String value = properties.getProperty(propertyName);

    if (value == null || value.isEmpty()) {
      String errorMsg = String.format("Value for property '%s' was not found, please check it",
              propertyName);
      throw new RuntimeException(errorMsg);
    }

    return value;
  }
}
