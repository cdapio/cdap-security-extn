/*
 * Copyright © 2016 Cask Data, Inc.
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

package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.common.UnauthorizedException;
import co.cask.cdap.common.conf.CConfiguration;
import co.cask.cdap.proto.ProgramType;
import co.cask.cdap.proto.id.ApplicationId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.NamespacedArtifactId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import org.junit.Assert;
import org.junit.Test;

import java.net.UnknownHostException;

/**
 * Test for {@link SentryAuthorizer}
 */
public class SentryAuthorizerTest {

  private final SentryAuthorizer authorizer;

  public SentryAuthorizerTest() throws UnknownHostException {
    String sentrySitePath = getClass().getClassLoader().getResource(AuthConf.SENTRY_SITE_FILENAME).getPath();
    CConfiguration cConf = CConfiguration.create();
    // put the sentry site path in cConf
    cConf.set(AuthConf.SENTRY_SITE_URL, "file://" + sentrySitePath);
    authorizer = new SentryAuthorizer(cConf);
  }

  @Test
  public void testValid() {
    testValid(new NamespaceId("ns1"));
    testValid(new StreamId("ns1", "stream1"));
    testValid(new DatasetId("ns1", "ds1"));
    testValid(new NamespacedArtifactId("ns1", "art", "1"));
    testValid(new ApplicationId("ns1", "app1"));
    testValid(new ProgramId("ns1", "app1", ProgramType.MAPREDUCE, "prog1"));

    // admin2 is admin of ns2
    testValid(new NamespaceId("ns2"), getUser("admin2"), Action.ADMIN);
    // user2 can read stream1 in ns2
    testValid(new StreamId("ns2", "stream1"), getUser("readers2"), Action.READ);

    // executors1 can execute prog1
    testValid(new ProgramId("ns1", "app1", ProgramType.MAPREDUCE, "prog1"), getUser("executors1"), Action.EXECUTE);
  }

  @Test
  public void testInvalid() {
    // do some invalid operations
    // admin1 is not admin of ns2
    testInvalid(new NamespaceId("ns2"), getUser("admin1"), Action.ADMIN);

    // user2 cannot read stream1 in ns1
    testInvalid(new StreamId("ns1", "stream1"), getUser("readers2"), Action.READ);

    // readers1 cannot write stream1 in ns1
    testInvalid(new StreamId("ns1", "stream1"), getUser("readers1"), Action.WRITE);
    // writers1 cannot write stream1 in ns1
    testInvalid(new StreamId("ns1", "stream1"), getUser("writers1"), Action.READ);
    // admin1 cannot read/write/all/execute on
    testInvalid(new StreamId("ns1", "stream1"), getUser("admin1"), Action.READ);
    testInvalid(new StreamId("ns1", "stream1"), getUser("admin1"), Action.WRITE);
    testInvalid(new StreamId("ns1", "stream1"), getUser("admin1"), Action.ALL);
    testInvalid(new StreamId("ns1", "stream1"), getUser("admin1"), Action.EXECUTE);
  }

  private void testValid(EntityId entityId) {
    // admin1 is admin of entity
    testValid(entityId, getUser("admin1"), Action.ADMIN);
    // reader1 can read entity
    testValid(entityId, getUser("readers1"), Action.READ);
    // writer1 can write entity
    testValid(entityId, getUser("writers1"), Action.WRITE);
    // all1 can read/write/admin to entity
    testValid(entityId, getUser("all1"), Action.WRITE);
    testValid(entityId, getUser("all1"), Action.READ);
    testValid(entityId, getUser("all1"), Action.ADMIN);
  }

  private void testValid(EntityId entityId, Principal principal, Action action) {
    try {
      authorizer.enforce(entityId, principal, action);
    } catch (UnauthorizedException e) {
      Assert.fail(String.format("Authorization failed: %s", e));
    }
  }

  private void testInvalid(EntityId entityId, Principal principal, Action action) {
    try {
      authorizer.enforce(entityId, principal, action);
      Assert.fail("The authorization check should have failed.");
    } catch (Exception e) {
      Assert.assertTrue(e instanceof UnauthorizedException);
    }
  }

  private Principal getUser(String name) {
    return new Principal(name, Principal.PrincipalType.USER);
  }
}
