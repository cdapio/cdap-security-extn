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
import io.cdap.cdap.proto.id.NamespacedEntityId;
import io.cdap.cdap.proto.security.ApplicationPermission;
import io.cdap.cdap.proto.security.InstancePermission;
import io.cdap.cdap.proto.security.NamespacePermission;
import io.cdap.cdap.proto.security.Permission;
import io.cdap.cdap.proto.security.StandardPermission;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Converter of {@link RolePermission} to {@link EntityTypeWithPermission}
 */
public class RolePermissionConverter {
  public static final String SYSTEM_NAMESPACE = "system";

  /**
   * Converters List of {@link RolePermission} to map of namespaces and Set of {@link EntityTypeWithPermission}
   *
   * @param permissions List of {@link RolePermission}
   * @param namespaces  List of namespaces
   * @return Map of namespaces and Set of {@link EntityTypeWithPermission}
   */
  public static Map<String, Set<EntityTypeWithPermission>> convert(List<RolePermission> permissions,
                                                                   List<String> namespaces) {
    // Finding all dependencies for permissions and mapping them to CDAP permissions and entities
    Set<EntityTypeWithPermission> principalPermissions = permissions.stream()
      .map(RolePermissionConverter::getPermissionWithDependencies)
      .distinct()
      .flatMap(Collection::stream)
      .map(RolePermissionConverter::convertToEntityTypeWithPermission)
      .flatMap(Collection::stream)
      .collect(Collectors.toSet());

    Map<String, Set<EntityTypeWithPermission>> result = new HashMap<>();

    // Filtering permissions for system namespace
    Set<EntityTypeWithPermission> systemPrincipalPermissions = principalPermissions.stream()
      .filter(EntityTypeWithPermission::isSystemNamespace)
      .collect(Collectors.toSet());

    // Setting permissions for system namespace and removing it from list of all namespaces if necessary
    List<String> nonSystemNamespaces = new ArrayList<>(namespaces);
    if (namespaces.contains(SYSTEM_NAMESPACE)) {
      nonSystemNamespaces.remove(SYSTEM_NAMESPACE);
      if (!principalPermissions.isEmpty()) {
        result.put(SYSTEM_NAMESPACE, principalPermissions);
      }
    } else if (!systemPrincipalPermissions.isEmpty()) {
      result.put(SYSTEM_NAMESPACE, systemPrincipalPermissions);
    }

    // Filtering permissions for non system namespace
    Set<EntityTypeWithPermission> nonSystemPrincipalPermission = new HashSet<>(principalPermissions);
    nonSystemPrincipalPermission.removeAll(systemPrincipalPermissions);

    if (!nonSystemPrincipalPermission.isEmpty()) {
      nonSystemNamespaces.forEach(namespace -> result.put(namespace, nonSystemPrincipalPermission));
    }

    return result;
  }

  /**
   * Converts {@link RolePermission} to list of {@link EntityTypeWithPermission}
   *
   * @param permission {@link RolePermission}
   * @return List of {@link EntityTypeWithPermission}
   */
  public static List<EntityTypeWithPermission> convertToEntityTypeWithPermission(RolePermission permission) {
    // Handling custom set of permissions
    switch (permission) {
      case CREATE_PIPELINE:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.APPLICATION, StandardPermission.CREATE),
          new EntityTypeWithPermission(EntityType.DATASET, StandardPermission.CREATE),
          new EntityTypeWithPermission(EntityType.APPLICATION, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.ARTIFACT, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.SYSTEM_APP_ENTITY, StandardPermission.USE)
        );
      case DELETE_PIPELINE:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.APPLICATION, StandardPermission.DELETE),
          new EntityTypeWithPermission(EntityType.DATASET, StandardPermission.DELETE)
        );
      case VIEW_PIPELINE:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.PROGRAM, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.PROGRAM_RUN, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.PROGRAMREFERENCE, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.APPLICATION, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.DATASET, StandardPermission.LIST),
          new EntityTypeWithPermission(EntityType.DATASET, StandardPermission.GET)
        );
      case VIEW_NAMESPACE:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.NAMESPACE, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.NAMESPACE, StandardPermission.LIST),
          new EntityTypeWithPermission(EntityType.ARTIFACT, StandardPermission.LIST)
        );
      case VIEW_SYSTEM_SERVICES:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.NAMESPACE, StandardPermission.GET, true),
          new EntityTypeWithPermission(EntityType.INSTANCE, StandardPermission.LIST, true),
          new EntityTypeWithPermission(EntityType.SYSTEM_SERVICE, StandardPermission.GET, true),
          new EntityTypeWithPermission(EntityType.SYSTEM_SERVICE, StandardPermission.LIST, true)
        );
      case MANAGE_SYSTEM_PREFERENCES:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.INSTANCE, StandardPermission.GET, true),
          new EntityTypeWithPermission(EntityType.INSTANCE, StandardPermission.UPDATE, true)
        );
      case VIEW_COMPUTE_PROFILE:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.LIST),
          new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.GET, true),
          new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.LIST, true)
        );
      case DEPLOY_ARTIFACTS:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.APPLICATION, StandardPermission.CREATE),
          new EntityTypeWithPermission(EntityType.APPLICATION, StandardPermission.DELETE),
          new EntityTypeWithPermission(EntityType.ARTIFACT, StandardPermission.CREATE),
          new EntityTypeWithPermission(EntityType.ARTIFACT, StandardPermission.GET),
          new EntityTypeWithPermission(EntityType.ARTIFACT, StandardPermission.LIST),
          new EntityTypeWithPermission(EntityType.ARTIFACT, StandardPermission.UPDATE),
          new EntityTypeWithPermission(EntityType.ARTIFACT, StandardPermission.DELETE),
          new EntityTypeWithPermission(EntityType.DATASET, StandardPermission.CREATE)
        );
      case USE_WRANGLER:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.APPLICATION, StandardPermission.GET, true),
          new EntityTypeWithPermission(EntityType.DATASET, StandardPermission.LIST, true),
          new EntityTypeWithPermission(EntityType.SYSTEM_APP_ENTITY, StandardPermission.USE)
        );
      case MANAGE_SECURE_KEY:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.SECUREKEY, StandardPermission.CREATE),
          new EntityTypeWithPermission(EntityType.SECUREKEY, StandardPermission.UPDATE),
          new EntityTypeWithPermission(EntityType.SECUREKEY, StandardPermission.LIST),
          new EntityTypeWithPermission(EntityType.SECUREKEY, StandardPermission.DELETE)
        );
      case MANAGE_SCM:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.NAMESPACE, NamespacePermission.READ_REPOSITORY),
          new EntityTypeWithPermission(EntityType.NAMESPACE, NamespacePermission.WRITE_REPOSITORY),
          new EntityTypeWithPermission(EntityType.NAMESPACE, NamespacePermission.UPDATE_REPOSITORY_METADATA)
        );
      case MANAGE_SYSTEM_APP_ENTITIES:
        return Arrays.asList(
          new EntityTypeWithPermission(EntityType.SYSTEM_APP_ENTITY, StandardPermission.CREATE),
          new EntityTypeWithPermission(EntityType.SYSTEM_APP_ENTITY, StandardPermission.UPDATE),
          new EntityTypeWithPermission(EntityType.SYSTEM_APP_ENTITY, StandardPermission.DELETE)
        );
    }

    Permission cdapPermission = getPermission(permission);
    EntityType entityType = getEntityType(permission);

    if (cdapPermission == null || entityType == null) {
      return Collections.emptyList();
    }

    // To work with studio it is necessary to have permissions to 'system' namespace
    boolean isSystemNamespace = !NamespacedEntityId.class.isAssignableFrom(entityType.getIdClass())
      || permission == RolePermission.USE_STUDIO;;

    return Collections.singletonList(new EntityTypeWithPermission(entityType, cdapPermission, isSystemNamespace));
  }

  private static Set<RolePermission> getPermissionWithDependencies(RolePermission permission) {
    Set<RolePermission> result = new HashSet<>();

    switch (permission) {
      case VIEW_PIPELINE:
      case VIEW_LOGS:
      case VIEW_METADATA:
      case VIEW_TAGS:
        result.add(RolePermission.VIEW_PIPELINE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case DEPLOY_PIPELINE:
      case CREATE_PIPELINE:
        result.add(RolePermission.CREATE_PIPELINE);
        result.add(RolePermission.USE_STUDIO);
        result.add(RolePermission.VIEW_PIPELINE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case EXECUTE_PIPELINE:
        result.add(RolePermission.EXECUTE_PIPELINE);
        result.add(RolePermission.VIEW_PIPELINE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case DELETE_PIPELINE:
        result.add(RolePermission.DELETE_PIPELINE);
        result.add(RolePermission.VIEW_PIPELINE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case PREVIEW_PIPELINE:
        result.add(RolePermission.PREVIEW_PIPELINE);
        result.add(RolePermission.VIEW_PIPELINE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case MODIFY_PIPELINE:
      case CREATE_TAG:
      case DELETE_TAG:
        result.add(RolePermission.MODIFY_PIPELINE);
        result.add(RolePermission.VIEW_PIPELINE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case CREATE_SCHEDULE:
      case CHANGE_SCHEDULE:
      case CREATE_TRIGGERS:
      case SET_TRIGGERS:
        result.add(permission);
        result.add(RolePermission.EXECUTE_PIPELINE);
        result.add(RolePermission.VIEW_PIPELINE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case CREATE_NAMESPACE:
        result.add(RolePermission.CREATE_NAMESPACE);
        result.add(RolePermission.MODIFY_NAMESPACE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case MODIFY_NAMESPACE:
        result.add(RolePermission.MODIFY_NAMESPACE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case DELETE_NAMESPACE:
        result.add(RolePermission.DELETE_NAMESPACE);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case DEPLOY_ARTIFACTS:
        result.add(RolePermission.DEPLOY_ARTIFACTS);
        result.add(RolePermission.DEPLOY_DRIVERS);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case DEPLOY_DRIVERS:
        result.add(RolePermission.DEPLOY_DRIVERS);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case CREATE_COMPUTE_PROFILE:
      case MODIFY_COMPUTE_PROFILE:
      case DELETE_COMPUTE_PROFILE:
        result.add(permission);
        result.add(RolePermission.VIEW_COMPUTE_PROFILE);
        break;
      case USE_WRANGLER:
      case USE_STUDIO:
        result.add(permission);
        result.add(RolePermission.VIEW_NAMESPACE);
        break;
      case MANAGE_SECURE_KEY:
        result.add(RolePermission.MANAGE_SECURE_KEY);
        result.add(RolePermission.VIEW_SECURE_KEY);
        break;
      default:
        result.add(permission);
    }

    return result;
  }

  private static Permission getPermission(RolePermission permission) {
    switch (permission) {
      case EXECUTE_PIPELINE:
      case CREATE_TRIGGERS:
      case SET_TRIGGERS:
      case CREATE_SCHEDULE:
      case CHANGE_SCHEDULE:
        return ApplicationPermission.EXECUTE;
      case MODIFY_PIPELINE:
      case MODIFY_NAMESPACE:
      case MODIFY_COMPUTE_PROFILE:
        return StandardPermission.UPDATE;
      case CREATE_PIPELINE:
      case CREATE_NAMESPACE:
      case DEPLOY_DRIVERS:
      case DEPLOY_PIPELINE:
      case CREATE_COMPUTE_PROFILE:
        return StandardPermission.CREATE;
      case DELETE_NAMESPACE:
      case DELETE_PIPELINE:
      case DELETE_COMPUTE_PROFILE:
        return StandardPermission.DELETE;
      case VIEW_NAMESPACE:
      case VIEW_SECURE_KEY:
        return StandardPermission.GET;
      case PREVIEW_PIPELINE:
        return ApplicationPermission.PREVIEW;
      case USE_STUDIO:
      case VIEW_COMPUTE_PROFILE:
        return StandardPermission.LIST;
      case INITIATE_AND_ACCEPT_TETHER:
        return InstancePermission.TETHER;
      case PERFORM_HEALTH_CHECK:
        return InstancePermission.HEALTH_CHECK;
    }
    return null;
  }

  private static EntityType getEntityType(RolePermission permission) {
    switch (permission) {
      case EXECUTE_PIPELINE:
        return EntityType.PROGRAM;
      case DELETE_PIPELINE:
      case PREVIEW_PIPELINE:
      case MODIFY_PIPELINE:
      case CREATE_PIPELINE:
      case CREATE_TRIGGERS:
      case SET_TRIGGERS:
      case CREATE_SCHEDULE:
      case CHANGE_SCHEDULE:
        return EntityType.APPLICATION;
      case DEPLOY_DRIVERS:
      case USE_STUDIO:
        return EntityType.ARTIFACT;
      case CREATE_NAMESPACE:
      case MODIFY_NAMESPACE:
      case DELETE_NAMESPACE:
      case VIEW_NAMESPACE:
        return EntityType.NAMESPACE;
      case CREATE_COMPUTE_PROFILE:
      case VIEW_COMPUTE_PROFILE:
      case MODIFY_COMPUTE_PROFILE:
      case DELETE_COMPUTE_PROFILE:
        return EntityType.PROFILE;
      case MANAGE_SECURE_KEY:
      case VIEW_SECURE_KEY:
        return EntityType.SECUREKEY;
      case INITIATE_AND_ACCEPT_TETHER:
      case PERFORM_HEALTH_CHECK:
        return EntityType.INSTANCE;
    }
    return null;
  }
}
