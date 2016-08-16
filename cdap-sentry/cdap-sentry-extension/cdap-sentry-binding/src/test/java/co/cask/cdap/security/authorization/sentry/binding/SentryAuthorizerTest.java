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

import co.cask.cdap.api.TxRunnable;
import co.cask.cdap.api.data.DatasetInstantiationException;
import co.cask.cdap.api.dataset.Dataset;
import co.cask.cdap.api.dataset.DatasetManagementException;
import co.cask.cdap.api.dataset.DatasetProperties;
import co.cask.cdap.api.dataset.InstanceNotFoundException;
import co.cask.cdap.api.security.store.SecureStoreData;
import co.cask.cdap.api.security.store.SecureStoreMetadata;
import co.cask.cdap.proto.ProgramType;
import co.cask.cdap.proto.id.ApplicationId;
import co.cask.cdap.proto.id.ArtifactId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import co.cask.tephra.TransactionFailureException;
import com.google.common.base.Joiner;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Properties;

/**
 * Test for {@link SentryAuthorizer}
 */
public class SentryAuthorizerTest {

  private final SentryAuthorizer authorizer;
  private static final String SUPERUSER_HULK = "hulk";
  private static final String SUPERUSER_SPIDERMAN = "spiderman";

  public SentryAuthorizerTest() throws Exception {
    URL resource = getClass().getClassLoader().getResource("sentry-site.xml");
    Assert.assertNotNull(resource);
    String sentrySitePath = resource.getPath();
    final Properties properties = new Properties();
    properties.put(AuthConf.SENTRY_SITE_URL, sentrySitePath);
    properties.put(AuthConf.INSTANCE_NAME, "cdap");
    properties.put(AuthConf.SUPERUSERS, Joiner.on(",").join(SUPERUSER_HULK, SUPERUSER_SPIDERMAN));
    properties.put(AuthConf.SENTRY_ADMIN_GROUP, "cdap");
    this.authorizer = new SentryAuthorizer();
    authorizer.initialize(new AuthorizationContext() {
      @Override
      public List<SecureStoreMetadata> listSecureData(String namespace) throws Exception {
        return Collections.emptyList();
      }

      @Override
      public SecureStoreData getSecureData(String namespace, String name) throws Exception {
        throw new NoSuchElementException(namespace + ":" + name);
      }

      @Override
      public void putSecureData(String namespace, String key, String data, String description,
                                Map<String, String> properties) throws IOException {
        // no-op
      }

      @Override
      public void deleteSecureData(String namespace, String key) throws IOException {
        // no-op
      }

      @Override
      public Principal getPrincipal() {
        return new Principal(System.getProperty("user.name"), Principal.PrincipalType.USER);
      }

      @Override
      public Properties getExtensionProperties() {
        return properties;
      }

      @Override
      public boolean datasetExists(String name) throws DatasetManagementException {
        return false;
      }

      @Override
      public String getDatasetType(String name) throws DatasetManagementException {
        throw new InstanceNotFoundException(name);
      }

      @Override
      public DatasetProperties getDatasetProperties(String name) throws DatasetManagementException {
        throw new InstanceNotFoundException(name);
      }

      @Override
      public void createDataset(String name, String type, DatasetProperties datasetProperties)
        throws DatasetManagementException {
        // no-op
      }

      @Override
      public void updateDataset(String name, DatasetProperties datasetProperties) throws DatasetManagementException {
        // no-op
      }

      @Override
      public void dropDataset(String name) throws DatasetManagementException {
        // no-op
      }

      @Override
      public void truncateDataset(String name) throws DatasetManagementException {
        // no-op
      }

      @Override
      public <T extends Dataset> T getDataset(String name) throws DatasetInstantiationException {
        throw new DatasetInstantiationException("Cannot get dataset through no-op AuthorizationContext");
      }

      @Override
      public <T extends Dataset> T getDataset(String namespace, String dataset) throws DatasetInstantiationException {
        throw new DatasetInstantiationException("Cannot get dataset through no-op AuthorizationContext");
      }

      @Override
      public <T extends Dataset> T getDataset(String name, Map<String, String> map)
        throws DatasetInstantiationException {
        throw new DatasetInstantiationException("Cannot get dataset through no-op AuthorizationContext");
      }

      @Override
      public <T extends Dataset> T getDataset(String namespace, String dataset,
                                              Map<String, String> properties) throws DatasetInstantiationException {
        throw new DatasetInstantiationException("Cannot get dataset through no-op AuthorizationContext");
      }

      @Override
      public void releaseDataset(Dataset dataset) {
        // no-op
      }

      @Override
      public void discardDataset(Dataset dataset) {
        // no-op
      }

      @Override
      public void execute(TxRunnable txRunnable) throws TransactionFailureException {
        // no-op
      }
    });
  }

  @Test
  public void testAuthorized() throws Exception {
    testAuthorized(new NamespaceId("ns1"));
    testAuthorized(new StreamId("ns1", "stream1"));
    testAuthorized(new DatasetId("ns1", "ds1"));
    testAuthorized(new ArtifactId("ns1", "art", "1"));
    testAuthorized(new ApplicationId("ns1", "app1"));
    testAuthorized(new ProgramId("ns1", "app1", ProgramType.FLOW, "prog1"));

    // admin2 is admin of ns2
    assertAuthorized(new NamespaceId("ns2"), getUser("admin2"), Action.ADMIN);
    // user2 can read stream1 in ns2
    assertAuthorized(new StreamId("ns2", "stream1"), getUser("readers2"), Action.READ);

    // executors1 can execute prog1
    assertAuthorized(new ProgramId("ns1", "app1", ProgramType.FLOW, "prog1"), getUser("executors1"),
                     Action.EXECUTE);
  }

  @Test
  public void testUnauthorized() throws Exception {
    // do some invalid operations
    // admin1 is not admin of ns2
    assertUnauthorized(new NamespaceId("ns2"), getUser("admin1"), Action.ADMIN);

    // user2 cannot read stream1 in ns1
    assertUnauthorized(new StreamId("ns1", "stream1"), getUser("readers2"), Action.READ);

    // readers1 cannot write stream1 in ns1
    assertUnauthorized(new StreamId("ns1", "stream1"), getUser("readers1"), Action.WRITE);
    // writers1 cannot write stream1 in ns1
    assertUnauthorized(new StreamId("ns1", "stream1"), getUser("writers1"), Action.READ);
    // admin1 cannot read/write/all/execute on
    assertUnauthorized(new StreamId("ns1", "stream1"), getUser("admin1"), Action.READ);
    assertUnauthorized(new StreamId("ns1", "stream1"), getUser("admin1"), Action.WRITE);
    assertUnauthorized(new StreamId("ns1", "stream1"), getUser("admin1"), Action.ALL);
    assertUnauthorized(new StreamId("ns1", "stream1"), getUser("admin1"), Action.EXECUTE);
  }

  @Test
  public void testHierarchy() throws Exception {
    // admin1 has ADMIN on ns1
    assertAuthorized(new NamespaceId("ns1"), getUser("admin1"), Action.ADMIN);
    // hence, admin1 should have ADMIN on any child of ns1, even a child that admin1 has not been given explicit ADMIN
    // access's on in the authz-provider.ini
    assertAuthorized(new StreamId("ns1", "notconfigured"), getUser("admin1"), Action.ADMIN);
    assertAuthorized(new DatasetId("ns1", "notconfigured"), getUser("admin1"), Action.ADMIN);
    assertAuthorized(new ArtifactId("ns1", "notconfigured", "1.0"), getUser("admin1"), Action.ADMIN);
    assertAuthorized(new ApplicationId("ns1", "notconfigured"), getUser("admin1"), Action.ADMIN);
    assertAuthorized(new ProgramId("ns1", "foo", ProgramType.SPARK, "bar"), getUser("admin1"), Action.ADMIN);

    // however, admin1 should not get ADMIN on a children of ns2 via hierarchy
    assertUnauthorized(new StreamId("ns2", "notconfigured"), getUser("admin1"), Action.ADMIN);
    assertUnauthorized(new DatasetId("ns2", "notconfigured"), getUser("admin1"), Action.ADMIN);
    assertUnauthorized(new ArtifactId("ns2", "notconfigured", "1.0"), getUser("admin1"), Action.ADMIN);
    assertUnauthorized(new ApplicationId("ns2", "notconfigured"), getUser("admin1"), Action.ADMIN);
    assertUnauthorized(new ProgramId("ns2", "foo", ProgramType.SPARK, "bar"), getUser("admin1"), Action.ADMIN);

    // readers1 have READ on app1 in ns1
    assertAuthorized(new ApplicationId("ns1", "app1"), getUser("readers1"), Action.READ);
    // as a result, readers1 should get READ on any program in app1, even ones that have not been explicitly
    // configured in authz-provider.ini
    assertAuthorized(new ProgramId("ns1", "app1", ProgramType.MAPREDUCE, "notconfigured"),
                     getUser("readers1"), Action.READ);
  }

  private void testAuthorized(EntityId entityId) throws Exception {
    // admin1 is admin of entity
    assertAuthorized(entityId, getUser("admin1"), Action.ADMIN);
    // reader1 can read entity
    assertAuthorized(entityId, getUser("readers1"), Action.READ);
    // writer1 can write entity
    assertAuthorized(entityId, getUser("writers1"), Action.WRITE);
    // all1 can read/write/admin to entity
    assertAuthorized(entityId, getUser("all1"), Action.WRITE);
    assertAuthorized(entityId, getUser("all1"), Action.READ);
    assertAuthorized(entityId, getUser("all1"), Action.ADMIN);
  }

  private void assertAuthorized(EntityId entityId, Principal principal, Action action) throws Exception {
    try {
      authorizer.enforce(entityId, principal, action);
    } catch (UnauthorizedException e) {
      Assert.fail(String.format("Authorization failed: %s", e));
    }
  }

  private void assertUnauthorized(EntityId entityId, Principal principal, Action action) throws Exception {
    try {
      authorizer.enforce(entityId, principal, action);
      Assert.fail("The authorization check should have failed.");
    } catch (UnauthorizedException expected) {
      // expected
    }
  }

  private Principal getUser(String name) {
    return new Principal(name, Principal.PrincipalType.USER);
  }
}
