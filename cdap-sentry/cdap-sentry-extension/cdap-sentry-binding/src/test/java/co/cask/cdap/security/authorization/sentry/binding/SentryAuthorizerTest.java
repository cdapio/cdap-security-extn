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
import co.cask.cdap.api.messaging.TopicAlreadyExistsException;
import co.cask.cdap.api.messaging.TopicNotFoundException;
import co.cask.cdap.api.security.store.SecureStoreData;
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
import com.google.common.base.Joiner;
import org.apache.hadoop.conf.Configuration;
import org.apache.tephra.TransactionFailureException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * Test for {@link SentryAuthorizer}
 */
public class SentryAuthorizerTest {

  @ClassRule
  public static final TemporaryFolder TEMPORARY_FOLDER = new TemporaryFolder();

  private static final String SUPERUSER_HULK = "hulk";
  private static final String SUPERUSER_SPIDERMAN = "spiderman";
  private static final int CACHE_TTL_SECS = 3;

  private static SentryAuthorizer authorizer;
  private static TestSentryService sentryService;

  @BeforeClass
  public static void setupTests() throws Exception {
    URL policyFileResource = SentryAuthorizer.class.getClassLoader().getResource("test-authz-provider.ini");
    Assert.assertNotNull("Cannot find policy file: test-authz-provider.ini", policyFileResource);
    sentryService = new TestSentryService(TEMPORARY_FOLDER.newFolder(), new File(policyFileResource.getPath()));
    sentryService.start();

    Configuration clientConfig = sentryService.getClientConfig();
    File sentrySite = TEMPORARY_FOLDER.newFile("sentry-site.xml");
    clientConfig.writeXml(new FileOutputStream(sentrySite));

    final Properties properties = new Properties();
    properties.put(AuthConf.SENTRY_SITE_URL, sentrySite.getAbsolutePath());
    properties.put(AuthConf.INSTANCE_NAME, "cdap");
    properties.put(AuthConf.SUPERUSERS, Joiner.on(",").join(SUPERUSER_HULK, SUPERUSER_SPIDERMAN));
    properties.put(AuthConf.SENTRY_ADMIN_GROUP, "cdap");
    properties.put(AuthConf.CACHE_MAX_ENTRIES, "100");
    properties.put(AuthConf.CACHE_TTL_SECS, String.valueOf(CACHE_TTL_SECS));
    authorizer = new SentryAuthorizer();
    authorizer.initialize(new AuthorizationContext() {
      @Override
      public Map<String, String> listSecureData(String namespace) throws Exception {
        return Collections.emptyMap();
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
      public void createTopic(String topic) throws TopicAlreadyExistsException, IOException {
        // no-op
      }

      @Override
      public void createTopic(String topic,
                              Map<String, String> properties) throws TopicAlreadyExistsException, IOException {
        // no-op
      }

      @Override
      public Map<String, String> getTopicProperties(String topic) throws TopicNotFoundException, IOException {
        return Collections.emptyMap();
      }

      @Override
      public void updateTopic(String topic, Map<String, String> properties) throws TopicNotFoundException, IOException {
        // no-op
      }

      @Override
      public void deleteTopic(String topic) throws TopicNotFoundException, IOException {
        // no-op
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

      @Override
      public void execute(int timeout, TxRunnable txRunnable) throws TransactionFailureException {
        // no-op
      }
    });
  }

  @AfterClass
  public static void tearDown() throws Exception {
    if (sentryService != null) {
      sentryService.stop();
    }
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
    assertUnauthorized(new StreamId("ns1", "stream1"), getUser("admin1"), Action.EXECUTE);
  }

  private void testAuthorized(EntityId entityId) throws Exception {
    // admin1 is admin of entity
    assertAuthorized(entityId, getUser("admin1"), Action.ADMIN);
    // readers1 can read entity
    assertAuthorized(entityId, getUser("readers1"), Action.READ);
    // writer1 can write entity
    assertAuthorized(entityId, getUser("writers1"), Action.WRITE);
    // all1 can read/write/admin to entity
    assertAuthorized(entityId, getUser("all1"), Action.WRITE);
    assertAuthorized(entityId, getUser("all1"), Action.READ);
    assertAuthorized(entityId, getUser("all1"), Action.ADMIN);
  }

  private void assertAuthorized(EntityId entityId, Principal principal, Action action) throws Exception {
    authorizer.enforce(entityId, principal, action);
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
