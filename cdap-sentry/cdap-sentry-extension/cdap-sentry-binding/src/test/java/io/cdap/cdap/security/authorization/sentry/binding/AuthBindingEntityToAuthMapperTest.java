/*
 * Copyright © 2016-2019 Cask Data, Inc.
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

package io.cdap.cdap.security.authorization.sentry.binding;

import com.google.common.collect.ImmutableSet;
import io.cdap.cdap.proto.ProgramType;
import io.cdap.cdap.proto.id.ApplicationId;
import io.cdap.cdap.proto.id.ArtifactId;
import io.cdap.cdap.proto.id.DatasetId;
import io.cdap.cdap.proto.id.DatasetModuleId;
import io.cdap.cdap.proto.id.DatasetTypeId;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.id.InstanceId;
import io.cdap.cdap.proto.id.KerberosPrincipalId;
import io.cdap.cdap.proto.id.NamespaceId;
import io.cdap.cdap.proto.id.ProgramId;
import io.cdap.cdap.proto.id.SecureKeyId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Privilege;
import io.cdap.cdap.security.authorization.sentry.model.Application;
import io.cdap.cdap.security.authorization.sentry.model.Artifact;
import io.cdap.cdap.security.authorization.sentry.model.Authorizable;
import io.cdap.cdap.security.authorization.sentry.model.Authorizable.AuthorizableType;
import io.cdap.cdap.security.authorization.sentry.model.Dataset;
import io.cdap.cdap.security.authorization.sentry.model.DatasetModule;
import io.cdap.cdap.security.authorization.sentry.model.DatasetType;
import io.cdap.cdap.security.authorization.sentry.model.Instance;
import io.cdap.cdap.security.authorization.sentry.model.Namespace;
import io.cdap.cdap.security.authorization.sentry.model.Principal;
import io.cdap.cdap.security.authorization.sentry.model.Program;
import io.cdap.cdap.security.authorization.sentry.model.SecureKey;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.URL;
import java.util.LinkedList;
import java.util.List;

/**
 * Test for {@link AuthBinding#toSentryAuthorizables(io.cdap.cdap.proto.security.Authorizable)}. For others please see
 * {@link SentryAuthorizerTest} since {@link SentryAuthorizer} delegates to {@link AuthBinding}
 */
public class AuthBindingEntityToAuthMapperTest {

  private static final String INSTANCE = "cdap";
  private static final String NAMESPACE = "n1";
  private static final String APPLICATION = "ap1";
  private static final String ARTIFACT = "ar1";
  private static final String ARTIFACT_VERSION = "0";
  private static final String DATASET = "d1";
  private static final String DATASET_MODULE = "dm";
  private static final String DATASET_TYPE = "dt";
  private static final String PROGRAM = "p1";
  private static final String SECUREKEY = "k1";
  private static final String PRINCIPAL = "alice";

  private static AuthBinding binding;

  @BeforeClass
  public static void setup() {
    URL resource = AuthBindingEntityToAuthMapperTest.class.getClassLoader().getResource("sentry-site.xml");
    Assert.assertNotNull(resource);
    String sentrySitePath = resource.getPath();
    binding = new AuthBinding(sentrySitePath, "cdap", null, 60, 100);
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

    // dataset
    entityId = new DatasetId(NAMESPACE, DATASET);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.DATASET), authorizables);

    // dataset module
    entityId = new DatasetModuleId(NAMESPACE, DATASET_MODULE);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.DATASET_MODULE), authorizables);

    // dataset type
    entityId = new DatasetTypeId(NAMESPACE, DATASET_TYPE);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.DATASET_TYPE), authorizables);

    // application
    entityId = new ApplicationId(NAMESPACE, APPLICATION);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.APPLICATION), authorizables);

    // program
    entityId = new ProgramId(NAMESPACE, APPLICATION, ProgramType.WORKER, PROGRAM);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.PROGRAM), authorizables);

    // securekey
    entityId = new SecureKeyId(NAMESPACE, SECUREKEY);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.SECUREKEY), authorizables);

    // principal
    entityId = new KerberosPrincipalId(PRINCIPAL);
    authorizables = binding.toSentryAuthorizables(entityId);
    Assert.assertEquals(getAuthorizablesList(AuthorizableType.PRINCIPAL), authorizables);
  }

  @Test
  public void testToPrivileges() {
    List<TSentryPrivilege> sentryPrivileges = new LinkedList<>();
    InstanceId instanceId = new InstanceId(INSTANCE);
    ArtifactId artifactId = new ArtifactId(NAMESPACE, ARTIFACT, ARTIFACT_VERSION);
    ProgramId programId = new ProgramId(NAMESPACE, APPLICATION, ProgramType.WORKER, PROGRAM);
    KerberosPrincipalId principalId = new KerberosPrincipalId(PRINCIPAL);

    sentryPrivileges.add(binding.toTSentryPrivilege(instanceId, Action.ADMIN));
    sentryPrivileges.add(binding.toTSentryPrivilege(artifactId, Action.READ));
    sentryPrivileges.add(binding.toTSentryPrivilege(programId, Action.WRITE));
    sentryPrivileges.add(binding.toTSentryPrivilege(principalId, Action.ADMIN));

    Assert.assertEquals(ImmutableSet.of(new Privilege(instanceId, Action.ADMIN),
                                        new Privilege(artifactId, Action.READ),
                                        new Privilege(programId, Action.WRITE),
                                        new Privilege(principalId, Action.ADMIN)),
                        binding.toPrivileges(sentryPrivileges));
  }

  private List<io.cdap.cdap.security.authorization.sentry.model.Authorizable> getAuthorizablesList(
    AuthorizableType authzType) {
    List<io.cdap.cdap.security.authorization.sentry.model.Authorizable> authzList = new LinkedList<>();
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
        authorizableList.add(new Artifact(ARTIFACT));
        break;
      case APPLICATION:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new Application(APPLICATION));
        break;
      case DATASET:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new Dataset(DATASET));
        break;
      case DATASET_MODULE:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new DatasetModule(DATASET_MODULE));
        break;
      case DATASET_TYPE:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new DatasetType(DATASET_TYPE));
        break;
      case PROGRAM:
        getAuthorizablesList(AuthorizableType.APPLICATION, authorizableList);
        authorizableList.add(new Program(ProgramType.WORKER, PROGRAM));
        break;
      case SECUREKEY:
        getAuthorizablesList(AuthorizableType.NAMESPACE, authorizableList);
        authorizableList.add(new SecureKey(SECUREKEY));
        break;
      case PRINCIPAL:
        getAuthorizablesList(AuthorizableType.INSTANCE, authorizableList);
        authorizableList.add(new Principal(PRINCIPAL));
        break;
      default:
        throw new IllegalArgumentException(String.format("Authorizable Types %s is invalid.", authzType));
    }
  }
}
