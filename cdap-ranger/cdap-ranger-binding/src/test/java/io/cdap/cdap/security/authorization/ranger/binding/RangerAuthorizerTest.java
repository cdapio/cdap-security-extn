/*
 * Copyright © 2017-2019 Cask Data, Inc.
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
package io.cdap.cdap.security.authorization.ranger.binding;

import io.cdap.cdap.proto.ProgramType;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.id.InstanceId;
import io.cdap.cdap.proto.id.NamespaceId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.collect.ImmutableSet;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Collections;
import java.util.Set;

/**
 * Test {@link RangerAuthorizer} through a policies stored in a file under resources/cdap-policies.json
 */
public class RangerAuthorizerTest {

  private static final NamespaceId NAMESPACE_DEFAULT = new NamespaceId("default");
  private static final Principal ALI = new Principal("ali", Principal.PrincipalType.USER);
  private static final Principal SAGAR = new Principal("sagar", Principal.PrincipalType.USER);
  private static final Principal SHANKAR = new Principal("shankar", Principal.PrincipalType.USER);
  private static final Principal MATT = new Principal("matt", Principal.PrincipalType.USER);
  private static final Principal POORNA = new Principal("poorna", Principal.PrincipalType.USER);
  private static final Principal RSINHA = new Principal("rsinha", Principal.PrincipalType.USER);
  private static final Principal DEREK = new Principal("derek", Principal.PrincipalType.USER);
  private static final Principal ALBERT = new Principal("albert", Principal.PrincipalType.USER);
  private static final Principal SREE = new Principal("sree", Principal.PrincipalType.USER);
  private static final Principal YAOJIE = new Principal("yaojie", Principal.PrincipalType.USER);

  private static RangerAuthorizer authorizer;

  @BeforeClass
  public static void setUp() throws Exception {
    authorizer = new RangerAuthorizer();
    authorizer.initialize(new InMemoryAuthorizationContext());
  }

  @Test
  public void testCompletePrivileges() throws Exception {
    // Test Privileges for ali who has ADMIN on stream:default:teststream
    authorizer.enforce(NAMESPACE_DEFAULT.stream("teststream"), ALI, Action.ADMIN);
    Assert.assertEquals(ImmutableSet.of(NAMESPACE_DEFAULT, NAMESPACE_DEFAULT.stream("teststream")),
                        authorizer.isVisible(ImmutableSet.<EntityId>of(NAMESPACE_DEFAULT,
                                                                       NAMESPACE_DEFAULT.stream("teststream")), ALI));
    testEnforceFail(NAMESPACE_DEFAULT.stream("anotherstream"), ALI, Action.ADMIN);
    testVisibleFail(ImmutableSet.<EntityId>of(new NamespaceId("anothernamespace")), ALI);
    testEnforceFail(NAMESPACE_DEFAULT.stream("teststream"), ALI, Action.READ);
    testEnforceFail(NAMESPACE_DEFAULT, ALI, Action.ADMIN);

    // Test privileges for rsinha who has ADMIN on namespace:default
    authorizer.enforce(NAMESPACE_DEFAULT, RSINHA, Action.ADMIN);
    testEnforceFail(new NamespaceId("anothernamespace"), RSINHA, Action.ADMIN);
    Assert.assertEquals(ImmutableSet.of(NAMESPACE_DEFAULT),
                        authorizer.isVisible(ImmutableSet.<EntityId>of(NAMESPACE_DEFAULT,
                                                                       NAMESPACE_DEFAULT.stream("teststream")),
                                             RSINHA));
    testVisibleFail(ImmutableSet.<EntityId>of(new NamespaceId("anothernamespace")), RSINHA);
    testEnforceFail(new InstanceId("cdap"), RSINHA, Action.ADMIN);
    testEnforceFail(NAMESPACE_DEFAULT, RSINHA, Action.WRITE);
    testEnforceFail(NAMESPACE_DEFAULT.stream("teststream"), RSINHA, Action.ADMIN);

    // Test Privileges for poorna who has READ on instance:cdap
    authorizer.enforce(new InstanceId("cdap"), POORNA, Action.READ);
    testVisibleFail(ImmutableSet.<EntityId>of(NAMESPACE_DEFAULT), POORNA);
    testEnforceFail(NAMESPACE_DEFAULT, POORNA, Action.READ);
    testEnforceFail(new InstanceId("cdap"), POORNA, Action.ADMIN);

    // Test privileges for matt who has READ and EXECUTE on program:anotherns.testapp.WORKFLOW.testworkflow
    authorizer.enforce(new NamespaceId("anotherns").app("testapp").program(ProgramType.WORKFLOW, "testworkflow"), MATT,
                       ImmutableSet.of(Action.READ, Action.EXECUTE));
    // test to make sure versions don't affect
    authorizer.enforce(
      new NamespaceId("anotherns").app("testapp", "1.0-SNAPSHOT").program(ProgramType.WORKFLOW, "testworkflow"),
      MATT, ImmutableSet.of(Action.READ, Action.EXECUTE)
    );
    testEnforceFail(new NamespaceId("anotherns").app("testapp").program(ProgramType.WORKFLOW, "anotherworkflow"), MATT,
                    Action.READ);
    testEnforceFail(new NamespaceId("anotherns").app("testapp").program(ProgramType.MAPREDUCE, "testworkflow"), MATT,
                    Action.READ);
    testEnforceFail(new NamespaceId("anotherns").app("testapp"), MATT, Action.READ);
    Assert.assertEquals(ImmutableSet.of(new NamespaceId("anotherns").app("testapp"),
                                        new NamespaceId("anotherns")),
                        authorizer.isVisible(ImmutableSet.<EntityId>of(new NamespaceId("anotherns").app("testapp"),
                                                                       new NamespaceId("anotherns")), MATT));
    testVisibleFail(ImmutableSet.<EntityId>of(NAMESPACE_DEFAULT), MATT);
    testEnforceFail(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.WORKFLOW, "testworkflow"), MATT,
                    Action.EXECUTE);

    // Test dataset type and module specifically as they can contain . in their names.
    authorizer.enforce(NAMESPACE_DEFAULT.datasetType("io.cdap.table_1_mod"), DEREK, Action.READ);
    testEnforceFail(new NamespaceId("anotherns").datasetType("io.cdap.table_1_mod"), DEREK, Action.READ);
    testEnforceFail(NAMESPACE_DEFAULT.datasetType("io.cdap"), DEREK, Action.READ);

    authorizer.enforce(NAMESPACE_DEFAULT.datasetModule("io.cdap.table_1_mod"), ALBERT, Action.READ);
    authorizer.enforce(NAMESPACE_DEFAULT.datasetModule("io.cdap.table_2_mod"), ALBERT, Action.READ);
    testEnforceFail(new NamespaceId("anotherns").datasetType("io.cdap.table_1_mod"), ALBERT, Action.READ);
    testEnforceFail(NAMESPACE_DEFAULT.datasetType("io.cdap"), ALBERT, Action.READ);

    // Test artifacts: we don't enforce on version for artifacts
    authorizer.enforce(NAMESPACE_DEFAULT.artifact("DataPipeline", "1.0-SNAPSHOT"), SREE, Action.READ);
    authorizer.enforce(NAMESPACE_DEFAULT.artifact("DataPipeline", "2.0-SNAPSHOT"), SREE, Action.READ);
    testEnforceFail(new NamespaceId("anotherns").artifact("DataPipeline", "1.0-SNAPSHOT"), SREE, Action.READ);
    // cdap entities are case sensitive
    testEnforceFail(NAMESPACE_DEFAULT.artifact("datapipeline", "1.0-SNAPSHOT"), SREE, Action.READ);
  }

  @Test
  public void testWildcardPrivileges() throws Exception {
    // Test privileges for sagar who has ADMIN on stream:default.*
    authorizer.enforce(NAMESPACE_DEFAULT.stream("teststream"), SAGAR, Action.ADMIN);
    authorizer.enforce(NAMESPACE_DEFAULT.stream("anotherstream"), SAGAR, Action.ADMIN);
    testEnforceFail(NAMESPACE_DEFAULT.stream("teststream"), SAGAR, Action.READ);
    testEnforceFail(NAMESPACE_DEFAULT, SAGAR, Action.ADMIN);
    Assert.assertEquals(ImmutableSet.of(NAMESPACE_DEFAULT, NAMESPACE_DEFAULT.stream("teststream")),
                        authorizer.isVisible(ImmutableSet.<EntityId>of(NAMESPACE_DEFAULT,
                                                                       NAMESPACE_DEFAULT.stream("teststream")), SAGAR));
    testVisibleFail(ImmutableSet.<EntityId>of(new NamespaceId("anothernamespace")), SAGAR);
    testEnforceFail(new NamespaceId("anothernamespace").stream("teststream"), SAGAR, Action.ADMIN);

    // Test privileges for shankar who has ADMIN on program:default.testapp.workflow.*
    authorizer.enforce(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.WORKFLOW, "prog1"), SHANKAR, Action.ADMIN);
    authorizer.enforce(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.WORKFLOW, "prog2"), SHANKAR, Action.ADMIN);
    testEnforceFail(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.MAPREDUCE, "prog1"), SHANKAR, Action.ADMIN);
    testEnforceFail(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.WORKFLOW, "prog1"), SHANKAR, Action.READ);
    testEnforceFail(NAMESPACE_DEFAULT.app("testapp"), SHANKAR, Action.ADMIN);
    Assert.assertEquals(ImmutableSet.of(NAMESPACE_DEFAULT.app("testapp"), NAMESPACE_DEFAULT),
                        authorizer.isVisible(ImmutableSet.<EntityId>of(NAMESPACE_DEFAULT.app("testapp"),
                                                                       NAMESPACE_DEFAULT), SHANKAR));
    testVisibleFail(ImmutableSet.<EntityId>of(new NamespaceId("anothernamespace")), SHANKAR);
    testVisibleFail(ImmutableSet.<EntityId>of(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.MAPREDUCE, "prog1")),
                    SHANKAR);

    // Test privileges for Yaojie who has EXECUTE on program:default.testapp.*
    authorizer.enforce(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.WORKFLOW, "prog1"), YAOJIE,
                       Action.EXECUTE);
    authorizer.enforce(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.WORKFLOW, "prog2"), YAOJIE,
                       Action.EXECUTE);
    authorizer.enforce(NAMESPACE_DEFAULT.app("testapp").program(ProgramType.MAPREDUCE, "prog1"), YAOJIE,
                       Action.EXECUTE);
    Assert.assertEquals(ImmutableSet.of(NAMESPACE_DEFAULT, NAMESPACE_DEFAULT.app("testapp")),
                        authorizer.isVisible(ImmutableSet.of(NAMESPACE_DEFAULT, NAMESPACE_DEFAULT.app("testapp")),
                                             YAOJIE));
    testEnforceFail(new NamespaceId("test").app("testapp").program(ProgramType.MAPREDUCE, "prog1"), YAOJIE,
                       Action.EXECUTE);
  }

  private void testEnforceFail(EntityId entityId, Principal principal, Action action) throws Exception {
    try {
      authorizer.enforce(entityId, principal, action);
      Assert.fail(String.format("Principal %s, should be unauthorized for %s on entity %s", entityId, principal,
                                action));
    } catch (UnauthorizedException e) {
      // expected
    }
  }

  private void testVisibleFail(Set<? extends EntityId> entities, Principal principal) throws Exception {
    Assert.assertEquals(Collections.EMPTY_SET, authorizer.isVisible(entities, principal));
  }
}
