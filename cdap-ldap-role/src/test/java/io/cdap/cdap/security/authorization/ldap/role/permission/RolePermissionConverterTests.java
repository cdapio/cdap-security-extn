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
import io.cdap.cdap.proto.security.StandardPermission;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tests for {@link RolePermissionConverter} class
 */
public class RolePermissionConverterTests {

  @Test
  public void testConvertWithDependencies() {
    String namespace = "test";
    List<RolePermission> rolePermissionList = Collections.singletonList(RolePermission.MODIFY_COMPUTE_PROFILE);

    Map<String, Set<EntityTypeWithPermission>> resultPermissions = RolePermissionConverter.convert(
      rolePermissionList, Collections.singletonList(namespace));

    Set<EntityTypeWithPermission> systemNamespacePermissionsSet = new HashSet<>(
      Arrays.asList(
        new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.GET, true),
        new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.LIST, true)
      )
    );
    Assert.assertEquals(systemNamespacePermissionsSet, resultPermissions.get(RolePermissionConverter.SYSTEM_NAMESPACE));

    Set<EntityTypeWithPermission> testNamespacePermissionsSet = new HashSet<>(
      Arrays.asList(
        new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.GET),
        new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.LIST),
        new EntityTypeWithPermission(EntityType.PROFILE, StandardPermission.UPDATE)
      )
    );
    Assert.assertEquals(testNamespacePermissionsSet, resultPermissions.get(namespace));
  }

  @Test
  public void testConvertToEntityTypeWithPermission() {
    List<EntityTypeWithPermission> permissions = RolePermissionConverter
      .convertToEntityTypeWithPermission(RolePermission.VIEW_SECURE_KEY);

    Assert.assertEquals(1, permissions.size());

    EntityTypeWithPermission entityTypeWithPermission = permissions.get(0);
    Assert.assertEquals(EntityType.SECUREKEY, entityTypeWithPermission.getEntityType());
    Assert.assertEquals(StandardPermission.GET, entityTypeWithPermission.getPermission());
    Assert.assertFalse(entityTypeWithPermission.isSystemNamespace());
  }
}
