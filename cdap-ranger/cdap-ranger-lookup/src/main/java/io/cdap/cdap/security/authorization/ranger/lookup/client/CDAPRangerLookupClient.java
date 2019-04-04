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
package io.cdap.cdap.security.authorization.ranger.lookup.client;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.base.Supplier;
import com.google.common.base.Throwables;
import io.cdap.cdap.api.artifact.ArtifactSummary;
import io.cdap.cdap.api.security.store.SecureStoreMetadata;
import io.cdap.cdap.cli.util.InstanceURIParser;
import io.cdap.cdap.client.ApplicationClient;
import io.cdap.cdap.client.ArtifactClient;
import io.cdap.cdap.client.DatasetClient;
import io.cdap.cdap.client.DatasetModuleClient;
import io.cdap.cdap.client.DatasetTypeClient;
import io.cdap.cdap.client.NamespaceClient;
import io.cdap.cdap.client.SecureStoreClient;
import io.cdap.cdap.client.config.ClientConfig;
import io.cdap.cdap.client.config.ConnectionConfig;
import io.cdap.cdap.proto.ApplicationRecord;
import io.cdap.cdap.proto.DatasetModuleMeta;
import io.cdap.cdap.proto.DatasetSpecificationSummary;
import io.cdap.cdap.proto.DatasetTypeMeta;
import io.cdap.cdap.proto.NamespaceMeta;
import io.cdap.cdap.proto.ProgramRecord;
import io.cdap.cdap.proto.id.ApplicationId;
import io.cdap.cdap.proto.id.NamespaceId;
import io.cdap.cdap.security.authentication.client.AccessToken;
import io.cdap.cdap.security.authentication.client.AuthenticationClient;
import io.cdap.cdap.security.authentication.client.basic.BasicAuthenticationClient;
import io.cdap.cdap.security.authorization.ranger.commons.RangerCommon;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.client.BaseClient;
import org.apache.ranger.plugin.service.ResourceLookupContext;
import org.apache.ranger.plugin.util.TimedEventUtil;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.annotation.Nullable;

/**
 * CDAP Clients which to be used by ranger for listing cdap resources.
 * Note: The log statements in this class are written in a formatted way to match the logging format
 * used by other services in Apache Ranger since these log statements end up in ranger admin log file we
 * want them to be in same format.
 */
public class CDAPRangerLookupClient {

  private static final Log LOG = LogFactory.getLog(CDAPRangerLookupClient.class);
  private static final long SERVICE_TIMEOUT_SECONDS = TimeUnit.MINUTES.toSeconds(3);
  private static final String ERR_MSG = " You can still save the repository and start creating "
    + "policies, but you would not be able to use autocomplete for "
    + "resource names. Check xa_portal.log for more info.";
  private final String instanceURL;
  private final String username;
  private final String password;
  private AuthenticationClient authClient;
  private NamespaceClient nsClient;
  private ApplicationClient applicationClient;
  private DatasetClient datasetClient;
  private ArtifactClient artifactClient;
  private DatasetModuleClient datasetModuleClient;
  private DatasetTypeClient datasetTypeClient;
  private SecureStoreClient secureStoreClient;

  CDAPRangerLookupClient(String instanceURL, String username, String password) throws IOException {
    this(instanceURL, username, password, true);
  }

  // for testing only. does not use authentication client
  @VisibleForTesting
  CDAPRangerLookupClient(String instanceURL, String username, String password,
                         NamespaceClient nsClient, ApplicationClient applicationClient,
                         DatasetClient datasetClient, ArtifactClient artifactClient,
                         DatasetModuleClient datasetModuleClient, DatasetTypeClient datasetTypeClient,
                         SecureStoreClient secureStoreClient) throws IOException {
    this(instanceURL, username, password, false);
    this.nsClient = nsClient;
    this.applicationClient = applicationClient;
    this.datasetClient = datasetClient;
    this.artifactClient = artifactClient;
    this.datasetModuleClient = datasetModuleClient;
    this.datasetTypeClient = datasetTypeClient;
    this.secureStoreClient = secureStoreClient;
  }

  private CDAPRangerLookupClient(String instanceURL, String username, String password, boolean initClients) throws
    IOException {
    this.instanceURL = instanceURL;
    this.username = username;
    this.password = password;
    if (initClients) {
      initConnection();
    }
  }

  private void initConnection() throws IOException {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient initConnection()");
    }
    if (username != null && password != null) {
      // security is enabled, we need to get access token before checking system services
      try {
        LOG.info(String.format("Fetching access token with username %s and password ****", username));
        initAuthClient(username, password);
        ClientConfig clientConfig = getClientConfig();
        this.nsClient = new NamespaceClient(clientConfig);
        this.datasetClient = new DatasetClient(clientConfig);
        this.applicationClient = new ApplicationClient(clientConfig);
        this.artifactClient = new ArtifactClient(clientConfig);
        this.datasetModuleClient = new DatasetModuleClient(clientConfig);
        this.datasetTypeClient = new DatasetTypeClient(clientConfig);
        this.secureStoreClient = new SecureStoreClient(clientConfig);
      } catch (Exception ex) {
        Throwables.propagateIfInstanceOf(ex, IOException.class);
        throw Throwables.propagate(ex);
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient initConnection()");
    }
  }

  /**
   * Tests that a connection can be established to CDAP with the given config. We do this by listing namespaces.
   *
   * @return Map &lt; String, Object &gt; Connection test response
   */
  Map<String, Object> testConnection() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient testConnection()");
    }
    HashMap<String, Object> responseData = new HashMap<>();
    try {
      getNamespaces(null);
      String successMsg = "Connection Test Successful";
      BaseClient.generateResponseDataMap(true, successMsg, successMsg,
                                         null, null, responseData);
    } catch (Exception e) {
      LOG.error("Error connecting to CDAP.", e);
      String failureMsg = "Unable to connect to CDAP instance." + e.getMessage();
      BaseClient.generateResponseDataMap(false, failureMsg,
                                         failureMsg + ERR_MSG, null, null, responseData);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient testConnection()");
    }
    return responseData;
  }

  public List<String> getResources(ResourceLookupContext context) {
    final String userInput = context.getUserInput();
    final String resource = context.getResourceName();
    final Map<String, List<String>> resourceMap = context.getResources();
    List<String> resultList = null;

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPResourceMgr.getResources()  UserInput: \"" + userInput + "\" resource : " + resource +
                  " resourceMap: " + resourceMap);
    }
    if (userInput != null && resource != null && resourceMap != null && !resourceMap.isEmpty()) {
      try {
        Callable<List<String>> callableObj = () -> {
          List<String> retList = new ArrayList<>();
          try {
            // note that in the the list calls resourceMap is used to exclude entities which has already been added
            // to the list being displayed to the user as an option for selection.
            List<String> list = null;
            NamespaceId namespace = null;
            // if user is still entering the namespace the resourceMap.get(RangerCommon.KEY_NAMESPACE).get(0) will
            // be empty string in that case we don't want to initialize the namespaceId
            if (resourceMap.containsKey(RangerCommon.KEY_NAMESPACE) &&
              !resourceMap.get(RangerCommon.KEY_NAMESPACE).isEmpty() &&
              !resourceMap.get(RangerCommon.KEY_NAMESPACE).get(0).isEmpty()) {
              namespace = new NamespaceId(resourceMap.get(RangerCommon.KEY_NAMESPACE).get(0));
            }
            switch (resource.trim().toLowerCase()) {
              case RangerCommon.KEY_NAMESPACE:
                list = getNamespaces(resourceMap.get(RangerCommon.KEY_NAMESPACE));
                break;
              case RangerCommon.KEY_APPLICATION:
                list = getApplications(namespace, resourceMap.get(RangerCommon.KEY_APPLICATION));
                break;
              case RangerCommon.KEY_DATASET:
                list = getDatasets(namespace, resourceMap.get(RangerCommon.KEY_DATASET));
                break;
              case RangerCommon.KEY_PROGRAM:
                Preconditions.checkNotNull(resourceMap.get(RangerCommon.KEY_APPLICATION));
                @SuppressWarnings("ConstantConditions")
                ApplicationId applicationId = new ApplicationId(namespace.getNamespace(), resourceMap.get
                  (RangerCommon.KEY_APPLICATION).get(0));
                list = getPrograms(applicationId, resourceMap.get(RangerCommon.KEY_PROGRAM));
                break;
              case RangerCommon.KEY_ARTIFACT:
                list = getArtifacts(namespace, resourceMap.get(RangerCommon.KEY_ARTIFACT));
                break;
              case RangerCommon.KEY_DATASET_MODULE:
                list = getDatasetModules(namespace, resourceMap.get(RangerCommon.KEY_DATASET_MODULE));
                break;
              case RangerCommon.KEY_DATASET_TYPE:
                list = getDatasetTypes(namespace, resourceMap.get(RangerCommon.KEY_DATASET_TYPE));
                break;
              case RangerCommon.KEY_SECUREKEY:
                list = getSecureKeys(namespace, resourceMap.get(RangerCommon.KEY_SECUREKEY));
                break;
              case RangerCommon.KEY_PRINCIPAL:
                // Cannot list principals
                list = Collections.emptyList();
            }
            Preconditions.checkNotNull(list, "Failed to list resources of type %s", resource.trim());
            if (!userInput.isEmpty()) {
              for (String value : list) {
                // programs are taken as programtype.programname but for matching purpose we only want to match on
                // the program name.
                String matchPart = value;
                if (resource.trim().toLowerCase().equalsIgnoreCase(RangerCommon.KEY_PROGRAM)) {
                  matchPart = value.substring(value.indexOf(".") + 1, value.length());
                }
                if (matchPart.startsWith(userInput)) {
                  retList.add(value);
                }
              }
            } else {
              retList.addAll(list);
            }
          } catch (Exception ex) {
            LOG.error("Error getting resource.", ex);
          }
          return retList;
        };

        synchronized (this) {
          resultList = TimedEventUtil.timedTask(callableObj, SERVICE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
      } catch (Exception e) {
        LOG.error("Unable to get CDAP resources.", e);
      }
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPResourceMgr.getCDAPResources() UserInput: " + userInput + " " + "Result :" + resultList);

    }
    return resultList;
  }

  private List<String> getNamespaces(@Nullable List<String> nsList) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getNamespaces() ExcludeNamespaceList :" + nsList);
    }

    List<String> namespaces = new ArrayList<>();
    if (nsClient != null) {
      for (NamespaceMeta namespaceMeta : nsClient.list()) {
        String name = namespaceMeta.getName();
        if (nsList == null || !nsList.contains(name)) {
          namespaces.add(name);
        }
      }
    } else {
      LOG.warn("Failed to get namespaces. NamespaceClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getNamespaces(): " + namespaces);
    }
    return namespaces;
  }

  private List<String> getDatasets(NamespaceId namespace, @Nullable List<String> datasetList) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getDatasets() ExcludeDatasetList :" + datasetList);
    }

    List<String> datasets = new ArrayList<>();
    if (datasetClient != null) {
      for (DatasetSpecificationSummary datasetSpecificationSummary : datasetClient.list(namespace)) {
        String name = datasetSpecificationSummary.getName();
        if (datasetList == null || !datasetList.contains(name)) {
          datasets.add(name);
        }
      }
    } else {
      LOG.warn("Failed to get Datasets. DatasetClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getDatasets(): " + datasets);
    }
    return datasets;
  }

  private List<String> getDatasetModules(NamespaceId namespace, @Nullable List<String> datasetModuleList) throws
    Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getDatasetModules() ExcludeDatasetModuleList :" + datasetModuleList);
    }

    List<String> datasetModules = new ArrayList<>();
    if (datasetModuleClient != null) {
      for (DatasetModuleMeta datasetSpecificationSummary : datasetModuleClient.list(namespace)) {
        String name = datasetSpecificationSummary.getName();
        if (datasetModuleList == null || !datasetModuleList.contains(name)) {
          datasetModules.add(name);
        }
      }
    } else {
      LOG.warn("Failed to get Datasets Modules. DatasetModuleClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getDatasetModules(): " + datasetModules);
    }
    return datasetModules;
  }

  private List<String> getDatasetTypes(NamespaceId namespace, @Nullable List<String> datasetTypeList) throws
    Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getDatasetTypes() ExcludeDatasetModuleList :" + datasetTypeList);
    }

    List<String> datasetTypes = new ArrayList<>();
    if (datasetTypeClient != null) {
      for (DatasetTypeMeta datasetTypeMeta : datasetTypeClient.list(namespace)) {
        String name = datasetTypeMeta.getName();
        if (datasetTypeList == null || !datasetTypeList.contains(name)) {
          datasetTypes.add(name);
        }
      }
    } else {
      LOG.warn("Failed to get Datasets Types. DatasetTypeClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getDatasetTypes(): " + datasetTypes);
    }
    return datasetTypes;
  }

  private List<String> getSecureKeys(NamespaceId namespace, @Nullable List<String> secureKeyList) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getSecureKeys() ExcludeArtifactList :" + secureKeyList);
    }

    List<String> secureKeys = new ArrayList<>();
    if (secureStoreClient != null) {
      for (SecureStoreMetadata meta : secureStoreClient.listKeys(namespace)) {
        if (secureKeyList == null || !secureKeys.contains(meta.getName())) {
          secureKeys.add(meta.getName());
        }
      }
    } else {
      LOG.warn("Failed to get Secure Keys. SecureStoreClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getSecureKeys(): " + secureKeys);
    }
    return secureKeys;
  }

  private List<String> getArtifacts(NamespaceId namespace, @Nullable List<String> artifactList) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getArtifacts() ExcludeArtifactList :" + artifactList);
    }

    List<String> artifacts = new ArrayList<>();
    if (artifactClient != null) {
      for (ArtifactSummary artifactSummary : artifactClient.list(namespace)) {
        String name = artifactSummary.getName();
        if (artifactList == null || !artifacts.contains(name)) {
          artifacts.add(name);
        }
      }
    } else {
      LOG.warn("Failed to get Artifacts. ArtifactClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getArtifacts(): " + artifacts);
    }
    return artifacts;
  }

  private List<String> getApplications(NamespaceId namespace, @Nullable List<String> appList) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getApplications() ExcludeApplicationList :" + appList);
    }

    List<String> applications = new ArrayList<>();
    if (applicationClient != null) {
      for (ApplicationRecord applicationRecord : applicationClient.list(namespace)) {
        String name = applicationRecord.getName();
        if (appList == null || !applications.contains(name)) {
          applications.add(name);
        }
      }
    } else {
      LOG.warn("Failed to get Applications. ApplicationClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getApplications(): " + applications);
    }
    return applications;
  }


  private List<String> getPrograms(ApplicationId appId, @Nullable List<String> programList) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getPrograms() ExcludeProgramList :" + programList);
    }

    List<String> programs = new ArrayList<>();
    if (applicationClient != null) {
      for (ProgramRecord programRecord : applicationClient.get(appId).getPrograms()) {
        String name = programRecord.getName();
        if (programList == null || !programs.contains(name)) {
          // we display program type as suffix because if its in prefix the lookup user will need to enter type first
          programs.add(Joiner.on(RangerCommon.RESOURCE_SEPARATOR).
            join(programRecord.getType().getPrettyName().toLowerCase(), name));
        }
      }
    } else {
      LOG.warn("Failed to get Programs. ApplicationClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getPrograms(): " + programs);
    }
    return programs;
  }

  /**
   * @return {@link ClientConfig}
   */
  private ClientConfig getClientConfig() {
    ClientConfig.Builder builder = new ClientConfig.Builder();
    builder.setConnectionConfig(InstanceURIParser.DEFAULT.parse(
      URI.create(instanceURL).toString()));
    builder.setAccessToken(fetchAccessToken());
    String verifySSL = System.getProperty("verifySSL");
    if (verifySSL != null) {
      builder.setVerifySSLCert(Boolean.valueOf(verifySSL));
    }
    builder.setDefaultConnectTimeout(45000);
    builder.setDefaultReadTimeout(45000);
    builder.setUploadConnectTimeout(0);
    builder.setUploadReadTimeout(0);

    return builder.build();
  }

  /**
   * Uses BasicAuthenticationClient to fetch {@link AccessToken}.
   *
   * @param username username to use while connecting
   * @param password password for the above given username
   */
  private void initAuthClient(String username, String password) {
    Properties properties = new Properties();
    properties.setProperty("security.auth.client.username", username);
    properties.setProperty("security.auth.client.password", password);
    authClient = new BasicAuthenticationClient();
    authClient.configure(properties);
    ConnectionConfig connectionConfig = getClientConfig().getConnectionConfig();
    authClient.setConnectionInfo(connectionConfig.getHostname(), connectionConfig.getPort(),
                                 connectionConfig.isSSLEnabled());
  }

  private Supplier<AccessToken> fetchAccessToken() {
    return () -> {
      try {
        checkServicesWithRetry(() -> authClient.getAccessToken() != null);
        return authClient.getAccessToken();
      } catch (Exception e) {
        throw Throwables.propagate(e);
      }
    };
  }

  /**
   * Checks for system services to be up for SERVICE_TIMEOUT_SECONDS with 1 second delay during checks
   */
  private void checkServicesWithRetry(Callable<Boolean> callable) throws TimeoutException, InterruptedException {
    long startingTime = System.currentTimeMillis();
    do {
      try {
        if (callable.call()) {
          return;
        }
      } catch (IOException e) {
        // We want to suppress and retry on IOException
      } catch (Throwable e) {
        // Also suppress and retry if the root cause is IOException
        Throwable rootCause = Throwables.getRootCause(e);
        if (!(rootCause instanceof IOException)) {
          // Throw if root cause is any other exception e.g. UnauthenticatedException
          throw Throwables.propagate(rootCause);
        }
      }
      TimeUnit.SECONDS.sleep(1);
    } while (System.currentTimeMillis() <= startingTime + SERVICE_TIMEOUT_SECONDS * 1000);
    // when we have passed the timeout and the check for services is not successful
    throw new TimeoutException("Unable to connect to CDAP Authentication service to obtain access token.");
  }
}
