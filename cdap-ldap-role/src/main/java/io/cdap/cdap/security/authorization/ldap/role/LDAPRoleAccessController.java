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

import io.cdap.cdap.api.security.AccessException;
import io.cdap.cdap.api.security.store.SecureStoreData;
import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.security.Authorizable;
import io.cdap.cdap.proto.security.GrantedPermission;
import io.cdap.cdap.proto.security.Permission;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.proto.security.Role;
import io.cdap.cdap.proto.security.StandardPermission;
import io.cdap.cdap.security.authorization.ldap.role.group.GroupWithRolesProvider;
import io.cdap.cdap.security.authorization.ldap.role.group.PrincipalPermissions;
import io.cdap.cdap.security.authorization.ldap.role.searcher.LDAPClient;
import io.cdap.cdap.security.authorization.ldap.role.searcher.LDAPClientImpl;
import io.cdap.cdap.security.authorization.ldap.role.searcher.LDAPSearchConfig;
import io.cdap.cdap.security.authorization.ldap.role.searcher.LDAPSearcher;
import io.cdap.cdap.security.spi.authorization.AccessController;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;
import io.cdap.cdap.security.spi.authorization.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;

/**
 * An implementation of {@link AccessController} to use LDAP and role mapping to provide RBAC
 */
public class LDAPRoleAccessController implements AccessController {
  private static final Logger LOG = LoggerFactory.getLogger(LDAPRoleAccessController.class);

  private LDAPSearcher searcherService;
  private GroupWithRolesProvider roleProvider;

  private boolean ignoreFullAccessUsers;
  private boolean loggingOnly;
  private boolean disablePermissionsPropagation;

  @Override
  public void initialize(AuthorizationContext context) {
    printExtensionInfo();
    Properties properties = context.getExtensionProperties();
    ignoreFullAccessUsers = RoleAuthorizationUtil.getIgnoreFullAccessUsersValue(properties);
    loggingOnly = RoleAuthorizationUtil.getLoggingOnlyValue(properties);
    disablePermissionsPropagation = RoleAuthorizationUtil.getDisablePermissionsPropagationValue(properties);

    LOG.info("Permission propagation is: '{}'", !disablePermissionsPropagation);

    roleProvider = RoleAuthorizationUtil.createLDAPGroupRoleProvider(properties);

    if (loggingOnly) {
      return;
    }

    roleProvider.start();

    LDAPSearchConfig searchConfig = createLDAPConfig(context);
    LDAPClient ldapClient = new LDAPClientImpl(searchConfig);
    ldapClient.testConnection();
    searcherService = new LDAPSearcher(searchConfig, ldapClient);
  }

  @Override
  public void destroy() {
    if (!loggingOnly) {
      roleProvider.stop();
    }
  }

  @Override
  public void enforce(EntityId entity, Principal principal, Set<? extends Permission> permissions)
    throws AccessException {
    String username = principal.getName();
    LOG.debug("enforce user: '{}' entity: '{}' permissions: '{}'", username, entity, permissions);

    // If we are not user with full access
    if ((roleProvider.isUserWithFullAccess(username) && !ignoreFullAccessUsers) || loggingOnly) {
      return;
    }

    PrincipalPermissions principalPermissions = getAllPermissions(username);
    Set<? extends Permission> userPermissionsList;

    // Propagation permissions if entity is not set and propagation is not disabled
    if (!disablePermissionsPropagation && !roleProvider.isEntityTypeDefined(entity.getEntityType())) {
      userPermissionsList = RoleAuthorizationUtil.getPropagatedPermissions(entity, permissions, principalPermissions);
    } else {
      userPermissionsList = principalPermissions.getPermissions(entity, permissions);
    }

    Set<Permission> difference = new HashSet<>(permissions);
    difference.removeAll(userPermissionsList);

    if (!difference.isEmpty()) {
      LOG.debug("Denied access '{}' to '{}' with permissions: '{}'", principal, entity.toString(), permissions);
      throw new UnauthorizedException(principal, difference, entity);
    }
  }

  @Override
  public void enforceOnParent(EntityType entityType, EntityId parentId, Principal principal, Permission permission)
    throws AccessException {
    String username = principal.getName();

    LOG.debug("enforceOnParent user: '{}' type: '{}' parent: '{}' permissions: '{}'", username, entityType, parentId,
              permission);

    // If we are not user with full access
    if ((roleProvider.isUserWithFullAccess(username) && !ignoreFullAccessUsers) || loggingOnly) {
      return;
    }

    if (!permission.isCheckedOnParent()) {
      throw new UnauthorizedException(principal, Collections.singleton(permission), parentId, entityType);
    }

    PrincipalPermissions principalPermissions = getAllPermissions(username);
    boolean isPermissionAllowed = isAccessible(entityType, parentId, permission, principalPermissions);

    if (!isPermissionAllowed) {
      LOG.debug("Denied access '{}' to '{}' on parent '{}' with permissions: '{}'", principal, entityType.toString(),
                parentId.toString(), permission);
      throw new UnauthorizedException(principal, Collections.singleton(permission), parentId, entityType);
    }
  }

  @Override
  public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal)
    throws AccessException {
    String username = principal.getName();

    LOG.debug("isVisible user: '{}' entity: '{}' ", username, entityIds);

    // If we are not user with full access
    if ((roleProvider.isUserWithFullAccess(username) && !ignoreFullAccessUsers) || loggingOnly) {
      return entityIds;
    }

    PrincipalPermissions principalPermissions = getAllPermissions(username);

    return entityIds.stream()
      .filter(entity -> isVisible(entity, principalPermissions))
      .collect(Collectors.toSet());
  }

  @Override
  public void createRole(Role role) throws AccessException {
    throw new AccessException("Method 'createRole' is not implemented, use external config file instead");
  }

  @Override
  public void dropRole(Role role) throws AccessException {
    throw new AccessException("Method 'dropRole' is not implemented, use external config file instead");
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws AccessException {
    throw new AccessException("Method 'addRoleToPrincipal' is not implemented, use external config file instead");
  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws AccessException {
    throw new AccessException("Method 'removeRoleFromPrincipal' is not implemented, use external config file instead");
  }

  @Override
  public Set<Role> listRoles(Principal principal) throws AccessException {
    throw new AccessException("Method 'listRoles' is not implemented, use external config file instead");
  }

  @Override
  public Set<Role> listAllRoles() throws AccessException {
    throw new AccessException("Method 'listAllRoles' is not implemented, use external config file instead");
  }

  @Override
  public void grant(Authorizable authorizable, Principal principal, Set<? extends Permission> set)
    throws AccessException {
    throw new AccessException("Method 'grant' is not implemented, use external config file instead");
  }

  @Override
  public void revoke(Authorizable authorizable, Principal principal, Set<? extends Permission> set)
    throws AccessException {
    throw new AccessException("Method 'revoke' is not implemented, use external config file instead");
  }

  @Override
  public void revoke(Authorizable authorizable) throws AccessException {
    throw new AccessException("Method 'revoke' is not implemented, use external config file instead");
  }

  @Override
  public Set<GrantedPermission> listGrants(Principal principal) throws AccessException {
    throw new AccessException("Method 'listGrants' is not implemented, use external config file instead");
  }

  PrincipalPermissions getAllPermissions(String username) {
    Set<String> groups = searcherService.searchGroups(username);
    return roleProvider.getPrincipalPermissions(groups);
  }

  private LDAPSearchConfig createLDAPConfig(AuthorizationContext context) {
    Properties properties = context.getExtensionProperties();
    LOG.info("Searching for LDAP properties in deployment...");
    LDAPSearchConfig searchConfig = RoleAuthorizationUtil.createSearchConfig(properties);

    if (Objects.isNull(searchConfig.getLookUpBindDN()) && Objects.isNull(searchConfig.getLookUpBindPassword())) {
      LOG.info("Properties '{}' and '{}' were empty in deployment", RoleAuthorizationConstants.LDAP_LOOKUP_BIND_DN,
               RoleAuthorizationConstants.LDAP_LOOKUP_BIND_PASSWORD);
      LOG.info("Searching for LDAP bind properties in SecureStore...");
      try {
        SecureStoreData storeData = context.get(RoleAuthorizationConstants.SYSTEM_NAMESPACE,
                                                RoleAuthorizationConstants.LDAP_BIND_DN);
        String bindDn = new String(storeData.get(), StandardCharsets.UTF_8);

        storeData = context.get(RoleAuthorizationConstants.SYSTEM_NAMESPACE, RoleAuthorizationConstants.LDAP_BIND_PASS);
        String bindPass = new String(storeData.get(), StandardCharsets.UTF_8);

        searchConfig.setLookUpBindDN(bindDn);
        searchConfig.setLookUpBindPassword(bindPass);
      } catch (Exception e) {
        throw new RuntimeException("Failed to get LDAP properties from SecureStore", e);
      }
    }

    return searchConfig;
  }

  private boolean isVisible(EntityId entityId, PrincipalPermissions principalPermissions) {
    return isAccessible(entityId.getEntityType(), entityId, StandardPermission.GET, principalPermissions);
  }

  private boolean isAccessible(EntityType entityType, EntityId entityId, Permission permission,
                               PrincipalPermissions principalPermissions) {
    // Propagation permissions if entity is not set and propagation is not disabled
    if (!disablePermissionsPropagation && !roleProvider.isEntityTypeDefined(entityType)) {
      return RoleAuthorizationUtil.getPropagatedPermission(entityId, permission, principalPermissions)
        .isPresent();
    } else {
      return principalPermissions
        .getPermission(entityType, entityId, permission)
        .isPresent();
    }
  }

  private void printExtensionInfo() {
    URLClassLoader classLoader = (URLClassLoader) getClass().getClassLoader();
    try {
      URL url = classLoader.findResource(RoleAuthorizationConstants.MANIFEST_PATH);
      Manifest manifest = new Manifest(url.openStream());
      Attributes attr = manifest.getMainAttributes();

      String title = attr.getValue(RoleAuthorizationConstants.MANIFEST_TITLE_NAME);
      LOG.info("Extension: {}", title);

      String version = attr.getValue(RoleAuthorizationConstants.MANIFEST_VERSION_NAME);
      LOG.info("Version: {}", version);

      String commitHash = attr.getValue(RoleAuthorizationConstants.MANIFEST_BUILD_COMMIT_HASH_NAME);
      LOG.info("Build-Commit-Hash: {}", commitHash);

      String buildTime = attr.getValue(RoleAuthorizationConstants.MANIFEST_BUILD_TIME_NAME);
      LOG.info("Build-Time: {}", buildTime);
    } catch (IOException e) {
      LOG.error("Failed to get extension information from Manifest", e);
    }
  }
}
