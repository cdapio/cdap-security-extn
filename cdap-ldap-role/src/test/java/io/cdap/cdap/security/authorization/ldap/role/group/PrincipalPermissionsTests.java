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

import io.cdap.cdap.proto.id.InstanceId;
import io.cdap.cdap.proto.id.NamespaceId;
import io.cdap.cdap.proto.security.Permission;
import io.cdap.cdap.proto.security.StandardPermission;
import io.cdap.cdap.security.authorization.ldap.role.permission.EntityTypeWithPermission;
import io.cdap.cdap.security.authorization.ldap.role.permission.RolePermissionConverter;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Tests for {@link PrincipalPermissions} class
 */
public class PrincipalPermissionsTests {
  private final String namespace = "test";

  @Test
  public void testGetPermissionsWithEmptyMap() {
    PrincipalPermissions principalPermissions = new PrincipalPermissions();
    NamespaceId namespaceId = new NamespaceId(namespace);
    Set<? extends Permission> permissions = principalPermissions.getPermissions(namespaceId,
                                                                      Collections.singleton(StandardPermission.GET));
    Assert.assertTrue(permissions.isEmpty());
  }

  @Test
  public void testGetPermissionWithNamespacedEntity() {
    Map<String, Set<EntityTypeWithPermission>> permissionsMap = new HashMap<>();
    NamespaceId namespaceId = new NamespaceId(namespace);
    Permission permission = StandardPermission.GET;
    EntityTypeWithPermission entityTypeWithPermission = new EntityTypeWithPermission(namespaceId.getEntityType(),
                                                                                     permission);
    permissionsMap.put(namespace, Collections.singleton(entityTypeWithPermission));
    PrincipalPermissions principalPermissions = new PrincipalPermissions(permissionsMap);

    boolean isPermissionAllowed = principalPermissions.getPermission(namespaceId, permission).isPresent();

    Assert.assertTrue(isPermissionAllowed);
  }

  @Test
  public void testGetPermissionWithNonNamespacedEntity() {
    Map<String, Set<EntityTypeWithPermission>> permissionsMap = new HashMap<>();
    InstanceId instanceId = new InstanceId("instance");
    Permission permission = StandardPermission.GET;
    EntityTypeWithPermission entityTypeWithPermission = new EntityTypeWithPermission(instanceId.getEntityType(),
                                                                                     permission,
                                                                                     true);
    permissionsMap.put(RolePermissionConverter.SYSTEM_NAMESPACE, Collections.singleton(entityTypeWithPermission));
    PrincipalPermissions principalPermissions = new PrincipalPermissions(permissionsMap);

    boolean isPermissionAllowed = principalPermissions.getPermission(instanceId, permission).isPresent();

    Assert.assertTrue(isPermissionAllowed);
  }
}
