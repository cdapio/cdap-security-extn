/*
 * Copyright © 2017 Cask Data, Inc.
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
package co.cask.cdap.security.authorization.ranger.binding;

import co.cask.cdap.api.TxRunnable;
import co.cask.cdap.api.data.DatasetInstantiationException;
import co.cask.cdap.api.dataset.Dataset;
import co.cask.cdap.api.dataset.DatasetManagementException;
import co.cask.cdap.api.dataset.DatasetProperties;
import co.cask.cdap.api.dataset.InstanceNotFoundException;
import co.cask.cdap.api.messaging.TopicAlreadyExistsException;
import co.cask.cdap.api.messaging.TopicNotFoundException;
import co.cask.cdap.api.security.store.SecureStoreData;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import org.apache.tephra.TransactionFailureException;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Properties;

/**
 * Dummy implementation of AuthorizationContext for {@link RangerAuthorizerTest}
 */
public class InMemoryAuthorizationContext implements AuthorizationContext {
  private final Properties properties = new Properties();

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
    return new Principal(System.getProperty("cdap"), Principal.PrincipalType.USER);
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
}
