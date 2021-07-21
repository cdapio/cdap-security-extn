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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.security.authorization.ldap.role.permission.EntityTypeWithPermission;
import io.cdap.cdap.security.authorization.ldap.role.permission.RolePermissionConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Provider of LDAP groups mapping to {@link PrincipalPermissions}
 */
public class GroupWithRolesProvider {
  private static final Logger LOG = LoggerFactory.getLogger(GroupWithRolesProvider.class);

  private static final long DEFAULT_UPDATE_INTERVAL_DELAY = 0;
  private static final long DEFAULT_UPDATE_INTERVAL = 5000;

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(new YAMLFactory());

  private final long updateDelay;
  private final long updateInterval;

  private final String path;
  private final AtomicReference<RoleWithGroupsMappingConfig> referenceToMappingConfig;
  private final AtomicReference<Set<EntityType>> referenceToSetEntityTypes;
  private final ScheduledExecutorService executorService;

  /**
   * Constructor with path
   *
   * @param path path to mapping config
   */
  public GroupWithRolesProvider(String path) {
    this(path, DEFAULT_UPDATE_INTERVAL_DELAY, DEFAULT_UPDATE_INTERVAL);
  }

  /**
   * Constructor wt path and intervals
   *
   * @param path           path to mapping config
   * @param updateDelay    update delay for config
   * @param updateInterval update interval for config
   */
  public GroupWithRolesProvider(String path, long updateDelay, long updateInterval) {
    this.path = path;
    this.updateDelay = updateDelay;
    this.updateInterval = updateInterval;

    RoleWithGroupsMappingConfig mappingConfig = new RoleWithGroupsMappingConfig();
    referenceToMappingConfig = new AtomicReference<>(mappingConfig);
    referenceToSetEntityTypes = new AtomicReference<>(Collections.emptySet());

    executorService = Executors.newScheduledThreadPool(1);
  }

  /**
   * Starts process of config parsing and updating
   */
  public void start() {
    LOG.info("Getting permissions from: {}", path);
    executorService.scheduleAtFixedRate(this::updateRoleMapping, updateDelay, updateInterval,
                                        TimeUnit.MILLISECONDS);
  }

  /**
   * Stops process of config parsing and updating
   */
  public void stop() {
    executorService.shutdown();
  }

  /**
   * Searches and convert permissions for set of groups
   *
   * @param groupNames Set of groups
   * @return {@link PrincipalPermissions}
   */
  public PrincipalPermissions getPrincipalPermissions(Set<String> groupNames) {
    RoleWithGroupsMappingConfig mappingConfig = referenceToMappingConfig.get();

    Map<String, Set<EntityTypeWithPermission>> permissionsMap = groupNames.stream()
      .map(this::getGroupRoles)
      .flatMap(Collection::stream)
      .map(this::convertToEntityTypeWithNamespacesAndPermission)
      .flatMap(map -> map.entrySet().stream())
      .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, this::mergeSets)
      );

    return new PrincipalPermissions(permissionsMap);
  }

  /**
   * Checks if Entity is defined in config
   *
   * @param entityType {@link EntityType}
   * @return If Entity is defined in config
   */
  public boolean isEntityTypeDefined(EntityType entityType) {
    return referenceToSetEntityTypes.get()
      .contains(entityType);
  }

  /**
   * Checks if user has full access
   *
   * @param username Name of user
   * @return If user has full access
   */
  public boolean isUserWithFullAccess(String username) {
    return referenceToMappingConfig.get()
      .getFullAccessUsers()
      .contains(username);
  }

  private void updateRoleMapping() {
    LOG.debug("Updating permissions from: {}", path);

    RoleWithGroupsMappingConfig mappingConfig;
    try {
      mappingConfig = OBJECT_MAPPER.readValue(new File(path), RoleWithGroupsMappingConfig.class);
    } catch (IOException e) {
      LOG.error("Failed to read config from '{}'", path, e);
      return;
    }

    Set<EntityType> setEntityTypes = mappingConfig
      .getRoles() // Get all roles
      .values()
      .stream()
      .map(Role::getPermissions) // Get all permissions
      .flatMap(Collection::stream)
      .map(RolePermissionConverter::convertToEntityTypeWithPermission) // Convert to CDAP permissions with EntityType
      .flatMap(Collection::stream)
      .map(EntityTypeWithPermission::getEntityType) // Get entity type
      .collect(Collectors.toSet());

    referenceToMappingConfig.set(mappingConfig);
    referenceToSetEntityTypes.set(setEntityTypes);
  }

  private List<RoleWithNamespaces> getGroupRoles(String groupName) {
    RoleWithGroupsMappingConfig mappingConfig = referenceToMappingConfig.get();
    GroupWithRoles groupRole = mappingConfig.getRoleMapping().get(groupName);

    if (groupRole == null) {
      LOG.debug("No roles for group '{}'", groupName);
      return Collections.emptyList();
    }

    return groupRole.getRoles();
  }

  private Map<String, Set<EntityTypeWithPermission>>
  convertToEntityTypeWithNamespacesAndPermission(RoleWithNamespaces roleWithNamespace) {
    String roleName = roleWithNamespace.getRole();
    List<String> namespaces = roleWithNamespace.getNamespaces();
    RoleWithGroupsMappingConfig mappingConfig = referenceToMappingConfig.get();
    Role role = mappingConfig.getRoles().get(roleName);

    if (role == null) {
      String errorMsg = String.format("No role: '%s' in config", roleName);
      throw new RuntimeException(errorMsg);
    }

    return RolePermissionConverter.convert(role.getPermissions(), namespaces);
  }

  private Set<EntityTypeWithPermission> mergeSets(Set<EntityTypeWithPermission> set1,
                                                  Set<EntityTypeWithPermission> set2) {
    Set<EntityTypeWithPermission> result = new HashSet<>();

    Stream.of(set1, set2)
      .filter(Objects::nonNull)
      .forEach(result::addAll);

    return result;
  }
}
