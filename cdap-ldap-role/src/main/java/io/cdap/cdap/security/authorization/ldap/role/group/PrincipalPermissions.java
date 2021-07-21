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

package io.cdap.cdap.security.authorization.ldap.role.group;

import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.id.NamespacedEntityId;
import io.cdap.cdap.proto.security.Permission;
import io.cdap.cdap.security.authorization.ldap.role.permission.EntityTypeWithPermission;
import io.cdap.cdap.security.authorization.ldap.role.permission.RolePermissionConverter;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Information about all permissions grouped by namespaces
 */
public class PrincipalPermissions {
  private final Map<String, Set<EntityTypeWithPermission>> namespacePermissions;

  /**
   * Default constructor
   */
  public PrincipalPermissions() {
    namespacePermissions = Collections.unmodifiableMap(new HashMap<>());
  }

  /**
   * Constructor with map of permissions
   *
   * @param namespacePermissions Map with permissions
   */
  public PrincipalPermissions(Map<String, Set<EntityTypeWithPermission>> namespacePermissions) {
    this.namespacePermissions = Collections.unmodifiableMap(new HashMap<>(namespacePermissions));
  }

  /**
   * Getting Optional of {@link Permission} for specific {@link EntityId} and {@link Permission}
   *
   * @param entityId   {@link EntityId}
   * @param permission {@link Permission}
   * @return Optional of {@link Permission}
   */
  public Optional<? extends Permission> getPermission(EntityId entityId, Permission permission) {
    return getPermission(entityId.getEntityType(), entityId, permission);
  }

  /**
   * Getting Optional of {@link Permission} for specific {@link EntityType}, {@link EntityId} and
   * {@link Permission}
   *
   * @param entityType {@link EntityType}
   * @param entityId   {@link EntityId}
   * @param permission {@link Permission}
   * @return Optional of {@link Permission}
   */
  public Optional<? extends Permission> getPermission(EntityType entityType, EntityId entityId,
                                                      Permission permission) {
    return getPermissions(entityType, entityId, Collections.singleton(permission))
      .stream()
      .findAny();
  }

  /**
   * Getting Set of {@link Permission} for specific {@link EntityId} and {@link Permission}
   *
   * @param entityId    {@link EntityId}
   * @param permissions Set of {@link Permission}
   * @return Set of {@link EntityTypeWithPermission}
   */
  public Set<? extends Permission> getPermissions(EntityId entityId, Set<? extends Permission> permissions) {
    return getPermissions(entityId.getEntityType(), entityId, permissions);
  }

  /**
   * Getting Set of {@link Permission} for specific {@link EntityType}, {@link EntityId} and
   * {@link Permission}
   *
   * @param entityType  {@link EntityType}
   * @param entityId    {@link EntityId}
   * @param permissions Set of {@link Permission}
   * @return Set of {@link Permission}
   */
  public Set<? extends Permission> getPermissions(EntityType entityType, EntityId entityId,
                                                  Set<? extends Permission> permissions) {
    String namespace = RolePermissionConverter.SYSTEM_NAMESPACE;

    // If EntityId has namespace attributes, otherwise checking in system namespace
    if (entityId instanceof NamespacedEntityId) {
      namespace = ((NamespacedEntityId) entityId).getNamespace();
    }

    return getPermissions(namespace, entityType, permissions);
  }

  /**
   * Getting Set of {@link Permission} for specific {@link EntityType}, namespace and
   * {@link Permission}
   *
   * @param namespace   Namespace
   * @param entityType  {@link EntityType}
   * @param permissions Set of {@link Permission}
   * @return Set of {@link Permission}
   */
  public Set<? extends Permission> getPermissions(String namespace, EntityType entityType,
                                                  Set<? extends Permission> permissions) {
    Set<EntityTypeWithPermission> entityTypeWithPermissionList = namespacePermissions.get(namespace);
    if (entityTypeWithPermissionList == null) {
      return Collections.emptySet();
    }

    return entityTypeWithPermissionList.stream()
      .filter(entityTypeWithPermission -> entityTypeWithPermission.getEntityType() == entityType)
      .map(EntityTypeWithPermission::getPermission)
      .filter(permissions::contains)
      .collect(Collectors.toSet());
  }
}
