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

package io.cdap.cdap.security.authorization.ldap.role.permission;

import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.proto.security.Permission;

import java.util.Objects;

/**
 * Combination of {@link EntityType} and {@link RolePermission}
 */
public class EntityTypeWithPermission {
  private final EntityType entityType;
  private final Permission permission;
  private final boolean systemNamespace;

  public EntityTypeWithPermission(EntityType entityType, Permission permission) {
    this.entityType = entityType;
    this.permission = permission;
    systemNamespace = false;
  }

  public EntityTypeWithPermission(EntityType entityType, Permission permission, boolean systemNamespace) {
    this.entityType = entityType;
    this.permission = permission;
    this.systemNamespace = systemNamespace;
  }

  public EntityType getEntityType() {
    return entityType;
  }

  public Permission getPermission() {
    return permission;
  }

  public boolean isSystemNamespace() {
    return systemNamespace;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    EntityTypeWithPermission that = (EntityTypeWithPermission) o;
    return systemNamespace == that.systemNamespace && entityType == that.entityType
      && Objects.equals(permission, that.permission);
  }

  @Override
  public int hashCode() {
    return Objects.hash(entityType, permission, systemNamespace);
  }
}
