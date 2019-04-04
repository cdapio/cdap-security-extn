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

import io.cdap.cdap.api.NamespaceSummary;
import io.cdap.cdap.api.TxRunnable;
import io.cdap.cdap.api.data.DatasetInstantiationException;
import io.cdap.cdap.api.dataset.Dataset;
import io.cdap.cdap.api.dataset.DatasetManagementException;
import io.cdap.cdap.api.dataset.DatasetProperties;
import io.cdap.cdap.api.dataset.InstanceNotFoundException;
import io.cdap.cdap.api.security.store.SecureStoreData;
import io.cdap.cdap.api.security.store.SecureStoreMetadata;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Properties;
import javax.annotation.Nullable;

/**
 * Dummy implementation of AuthorizationContext for {@link RangerAuthorizerTest}
 */
public class InMemoryAuthorizationContext implements AuthorizationContext {
  private final Properties properties = new Properties();

  @Override
  public List<SecureStoreMetadata> list(String namespace) {
    return Collections.emptyList();
  }

  @Override
  public SecureStoreData get(String namespace, String name) {
    throw new NoSuchElementException(namespace + ":" + name);
  }

  @Override
  public void put(String namespace, String key, String data, String description, Map<String, String> properties) {
    // no-op
  }

  @Override
  public void delete(String namespace, String key) {
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
  public void createTopic(String topic) {
    // no-op
  }

  @Override
  public void createTopic(String topic,
                          Map<String, String> properties) {
    // no-op
  }

  @Override
  public Map<String, String> getTopicProperties(String topic) {
    return Collections.emptyMap();
  }

  @Override
  public void updateTopic(String topic, Map<String, String> properties) {
    // no-op
  }

  @Override
  public void deleteTopic(String topic) {
    // no-op
  }

  @Override
  public boolean datasetExists(String name) {
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
  public void createDataset(String name, String type, DatasetProperties datasetProperties) {
    // no-op
  }

  @Override
  public void updateDataset(String name, DatasetProperties datasetProperties) {
    // no-op
  }

  @Override
  public void dropDataset(String name) {
    // no-op
  }

  @Override
  public void truncateDataset(String name) {
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
  public void execute(TxRunnable txRunnable) {
    // no-op
  }

  @Override
  public void execute(int timeout, TxRunnable txRunnable) {
    // no-op
  }

  @Override
  public boolean namespaceExists(String s) {
    return false;
  }

  @Nullable
  @Override
  public NamespaceSummary getNamespaceSummary(String s) {
    return null;
  }
}
