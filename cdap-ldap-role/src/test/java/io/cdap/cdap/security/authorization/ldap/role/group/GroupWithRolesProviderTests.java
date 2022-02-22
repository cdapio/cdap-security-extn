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
import io.cdap.cdap.proto.id.DatasetId;
import io.cdap.cdap.proto.id.NamespaceId;
import io.cdap.cdap.proto.security.StandardPermission;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Tests for {@link GroupWithRolesProvider} class
 */
public class GroupWithRolesProviderTests {
  private static final String PATH = "src/test/resources/roles.yaml";
  private static GroupWithRolesProvider provider;

  @BeforeClass
  public static void init() throws InterruptedException {
    provider = new GroupWithRolesProvider(PATH);
    provider.start();
    Thread.sleep(2000);
  }

  @AfterClass
  public static void destroy() {
    provider.stop();
  }

  @Test
  public void testGetPrincipalPermissions() {
    String namespace = "namespace1";
    Set<String> groupList = new HashSet<>(
      Arrays.asList(
        "CN=operator1,OU=groups,DC=test,DC=local",
        "CN=operator2,OU=groups,DC=test,DC=local"
      )
    );

    NamespaceId namespaceId = new NamespaceId(namespace);
    PrincipalPermissions principalPermissions = provider.getPrincipalPermissions(groupList);
    boolean namespaceCreateAllowed =  principalPermissions.getPermission(namespaceId, StandardPermission.CREATE)
      .isPresent();
    Assert.assertTrue(namespaceCreateAllowed);

    DatasetId datasetId = new DatasetId(namespace, "$");
    boolean datasetListAllowed =  principalPermissions.getPermission(datasetId, StandardPermission.LIST).isPresent();
    Assert.assertTrue(datasetListAllowed);
  }

  @Test
  public void testIsEntityTypeDefined() {
    EntityType entityType = EntityType.ARTIFACT;
    boolean isArtifactDefined = provider.isEntityTypeDefined(entityType);

    Assert.assertFalse(isArtifactDefined);
  }
}
