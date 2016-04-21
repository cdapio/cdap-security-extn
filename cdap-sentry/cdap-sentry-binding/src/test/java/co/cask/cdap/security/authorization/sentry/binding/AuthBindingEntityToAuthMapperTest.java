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

import co.cask.cdap.proto.ProgramType;
import co.cask.cdap.proto.id.ApplicationId;
import co.cask.cdap.proto.id.ArtifactId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.InstanceId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.security.authorization.sentry.model.Application;
import co.cask.cdap.security.authorization.sentry.model.Artifact;
import co.cask.cdap.security.authorization.sentry.model.Authorizable;
import co.cask.cdap.security.authorization.sentry.model.Authorizable.AuthorizableType;
import co.cask.cdap.security.authorization.sentry.model.Dataset;
import co.cask.cdap.security.authorization.sentry.model.Instance;
import co.cask.cdap.security.authorization.sentry.model.Namespace;
import co.cask.cdap.security.authorization.sentry.model.Program;
import co.cask.cdap.security.authorization.sentry.model.Stream;
import com.google.common.collect.ImmutableSet;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.URL;
import java.util.LinkedList;
import java.util.List;

/**
 * Test for {@link AuthBinding#toSentryAuthorizables(EntityId)}. For others please see
 * {@link SentryAuthorizerTest} since {@link SentryAuthorizer} delegates to {@link AuthBinding}
 */
public class AuthBindingEntityToAuthMapperTest {

  private static final String INSTANCE = "cdap";
  private static final String NAMESPACE = "n1";
  private static final String APPLICATION = "ap1";
  private static final String ARTIFACT = "ar1";
  private static final String ARTIFACT_VERSION = "0";
  private static final String STREAM = "s1";
  private static final String DATASET = "d1";
  private static final String PROGRAM = "p1";

  private static AuthBinding binding;

  @BeforeClass
  public static void setup() {
    URL resource = AuthBindingEntityToAuthMapperTest.class.getClassLoader().getResource("sentry-site.xml");
    Assert.assertNotNull(resource);
    String sentrySitePath = resource.getPath();
    binding = new AuthBinding(sentrySitePath, "superUser", "cdap");
  }

  @Test
  public void testValidEntities() {

    // instance
    EntityId entityId = new InstanceId(INSTANCE);
    List<org.apache.sentry.core.common.Authorizable> authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.INSTANCE), authorizables);

    // namespace
    entityId = new NamespaceId(NAMESPACE);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.NAMESPACE), authorizables);

    // artifact
    entityId = new ArtifactId(NAMESPACE, ARTIFACT, ARTIFACT_VERSION);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.ARTIFACT), authorizables);

    // stream
    entityId = new StreamId(NAMESPACE, STREAM);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.STREAM), authorizables);

    // dataset
    entityId = new DatasetId(NAMESPACE, DATASET);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.DATASET), authorizables);

    // application
    entityId = new ApplicationId(NAMESPACE, APPLICATION);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.APPLICATION), authorizables);

    // program
    entityId = new ProgramId(NAMESPACE, APPLICATION, ProgramType.FLOW, PROGRAM);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.PROGRAM), authorizables);
  }

  @Test
  public void testToPrivileges() {
    List<TSentryPrivilege> sentryPrivileges = new LinkedList<>();
    InstanceId instanceId = new InstanceId(INSTANCE);
    ArtifactId artifactId = new ArtifactId(NAMESPACE, ARTIFACT, ARTIFACT_VERSION);
    ProgramId programId = new ProgramId(NAMESPACE, APPLICATION, ProgramType.FLOW, PROGRAM);

    sentryPrivileges.add(binding.toTSentryPrivilege(instanceId, Action.ADMIN));
    sentryPrivileges.add(binding.toTSentryPrivilege(artifactId, Action.READ));
    sentryPrivileges.add(binding.toTSentryPrivilege(programId, Action.WRITE));

    Assert.assertEquals(ImmutableSet.of(new Privilege(instanceId, Action.ADMIN),
                                        new Privilege(artifactId, Action.READ),
                                        new Privilege(programId, Action.WRITE)),
                        binding.toPrivileges(sentryPrivileges));
  }

  private List<co.cask.cdap.security.authorization.sentry.model.Authorizable> getAuthorizablesList(
    AuthorizableType authzType) {
    List<co.cask.cdap.security.authorization.sentry.model.Authorizable> authzList = new LinkedList<>();
    getAuthorizablesList(authzType, authzList);
    return authzList;
  }

  private void getAuthorizablesList(AuthorizableType authzType, List<Authorizable> authorizableList) {
    switch (authzType) {
      case INSTANCE:
        authorizableList.clear();
        authorizableList.add(new Instance(INSTANCE));
        break;
      case NAMESPACE:
        getAuthorizablesList(AuthorizableType.INSTANCE, authorizableList);
        authorizableList.add(new Namespace(NAMESPACE));
        break;
      case ARTIFACT:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new Artifact(ARTIFACT, ARTIFACT_VERSION));
        break;
      case APPLICATION:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new Application(APPLICATION));
        break;
      case STREAM:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new Stream(STREAM));
        break;
      case DATASET:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new Dataset(DATASET));
        break;
      case PROGRAM:
        getAuthorizablesList(AuthorizableType.APPLICATION, authorizableList);
        authorizableList.add(new Program(ProgramType.FLOW, PROGRAM));
        break;
      default:
        throw new IllegalArgumentException(String.format("Authorizable Types %s is invalid.", authzType));
    }
  }
}
