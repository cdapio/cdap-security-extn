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
package co.cask.cdap.security.authorization.ranger.lookup.client;

import co.cask.cdap.cli.util.InstanceURIParser;
import co.cask.cdap.client.ApplicationClient;
import co.cask.cdap.client.DatasetClient;
import co.cask.cdap.client.NamespaceClient;
import co.cask.cdap.client.StreamClient;
import co.cask.cdap.client.config.ClientConfig;
import co.cask.cdap.client.config.ConnectionConfig;
import co.cask.cdap.proto.ApplicationRecord;
import co.cask.cdap.proto.DatasetSpecificationSummary;
import co.cask.cdap.proto.NamespaceMeta;
import co.cask.cdap.proto.StreamDetail;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.security.authentication.client.AccessToken;
import co.cask.cdap.security.authentication.client.AuthenticationClient;
import co.cask.cdap.security.authentication.client.basic.BasicAuthenticationClient;
import co.cask.cdap.security.authorization.ranger.commons.RangerCommons;
import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.client.BaseClient;
import org.apache.ranger.plugin.service.ResourceLookupContext;
import org.apache.ranger.plugin.util.TimedEventUtil;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
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
  private static final long SERVICE_TIMEOUT_SECONDS = TimeUnit.MINUTES.toSeconds(30);
  private static final String ERR_MSG = " You can still save the repository and start creating "
    + "policies, but you would not be able to use autocomplete for "
    + "resource names. Check xa_portal.log for more info.";
  private final String serviceName;
  private final String instanceURL;
  private final String username;
  private final String password;
  private final NamespaceClient nsClient;
  private final StreamClient streamClient;
  private final ApplicationClient applicationClient;
  private final DatasetClient datasetClient;
  private AccessToken accessToken;

  CDAPRangerLookupClient(String serviceName, String instanceURL, String username, String password) {
    this.serviceName = serviceName;
    this.instanceURL = instanceURL;
    this.username = username;
    this.password = password;
    initConnection();
    ClientConfig clientConfig = getClientConfig();
    this.nsClient = new NamespaceClient(clientConfig);
    this.streamClient = new StreamClient(clientConfig);
    this.datasetClient = new DatasetClient(clientConfig);
    this.applicationClient = new ApplicationClient(clientConfig);
    //TODO create more cdap clients here
  }

  private void initConnection() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient initConnection()");
    }
    if (username != null && password != null) {
      // security is enabled, we need to get access token before checking system services
      try {
        LOG.info(String.format("Fetching access token with username %s and password ****", username));
        accessToken = fetchAccessToken(username, password);
      } catch (Exception ex) {
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
   * @return Map<String, Object> Connection test response
   */
  Map<String, Object> testConnection() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient testConnection()");
    }
    HashMap<String, Object> responseData = new HashMap<>();
    List<String> testResult;
    try {
      testResult = getNamespaces(null);
      if (testResult.size() >= 0) {
        String successMsg = "Connection Test Successful";
        BaseClient.generateResponseDataMap(true, successMsg, successMsg,
                                           null, null, responseData);
      }
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
    Map<String, List<String>> resourceMap = context.getResources();
    List<String> resultList = null;
    List<String> instanceList = null;
    List<String> namespaceList = null;
    List<String> streamList = null;
    List<String> datasetList = null;
    List<String> appList = null;


    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPResourceMgr.getResources()  UserInput: \"" + userInput + "\" resource : " + resource +
                  " resourceMap: " + resourceMap);
    }
    if (userInput != null && resource != null) {
      if (resourceMap != null && !resourceMap.isEmpty()) {
        instanceList = resourceMap.get(RangerCommons.KEY_INSTANCE);
        namespaceList = resourceMap.get(RangerCommons.KEY_NAMESPACE);
        streamList = resourceMap.get(RangerCommons.KEY_STREAM);
        appList = resourceMap.get(RangerCommons.KEY_APPLICATION);
        datasetList = resourceMap.get(RangerCommons.KEY_DATASET);
      }

      try {
        Callable<List<String>> callableObj;

        final List<String> finalnamespaceList = namespaceList;
        final List<String> finalStreamList = streamList;
        final List<String> finalAppList = appList;
        final List<String> finalDatasetList = datasetList;

        // get the DBList for given Input
        callableObj = new Callable<List<String>>() {
          @Override
          public List<String> call() {
            List<String> retList = new ArrayList<>();
            try {
              List<String> list = null;
              if (resource.trim().equalsIgnoreCase(RangerCommons.KEY_NAMESPACE)) {
                list = getNamespaces(finalnamespaceList);
              } else {
                Preconditions.checkNotNull(finalnamespaceList);
                NamespaceId namespace = new NamespaceId(finalnamespaceList.get(0));
                if (resource.trim().equalsIgnoreCase(RangerCommons.KEY_STREAM)) {
                  list = getStreams(finalStreamList, namespace);
                } else if (resource.trim().equalsIgnoreCase(RangerCommons.KEY_APPLICATION)) {
                  list = getApplications(finalAppList, namespace);
                } else if (resource.trim().equalsIgnoreCase(RangerCommons.KEY_DATASET)) {
                  list = getDatasets(finalDatasetList, namespace);
                }
              }
              Preconditions.checkNotNull(list, "Failed to list resources of type %s", resource.trim());
              if (!userInput.isEmpty()) {
                for (String value : list) {
                  if (value.startsWith(userInput)) {
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
          }
        };

        synchronized (this) {
          resultList = TimedEventUtil.timedTask(callableObj, SERVICE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
      } catch (Exception e) {
        LOG.error("Unable to get CDAP resources.", e);
      }
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPResourceMgr.getCDAPResources() UserInput: " + userInput + " " +
                  "instanceList: " + instanceList + " namespaceList: "
                  + namespaceList + "Result :" + resultList);

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

  private List<String> getStreams(@Nullable List<String> streamList, NamespaceId namespace) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPRangerLookupClient.getStreams() ExcludeStreamList :" + streamList);
    }

    List<String> streams = new ArrayList<>();
    if (streamClient != null) {
      for (StreamDetail streamDetail : streamClient.list(namespace)) {
        String name = streamDetail.getName();
        if (streamList == null || !streamList.contains(name)) {
          streams.add(name);
        }
      }
    } else {
      LOG.warn("Failed to get Stream. StreamClient is not initialized.");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPRangerLookupClient.getStreams(): " + streams);
    }
    return streams;
  }

  private List<String> getDatasets(@Nullable List<String> datasetList, NamespaceId namespace) throws Exception {
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

  private List<String> getApplications(@Nullable List<String> appList, NamespaceId namespace) throws Exception {
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

  /**
   * @return {@link ClientConfig}
   */
  private ClientConfig getClientConfig() {
    ClientConfig.Builder builder = new ClientConfig.Builder();
    builder.setConnectionConfig(InstanceURIParser.DEFAULT.parse(
      URI.create(instanceURL).toString()));

    if (accessToken != null) {
      builder.setAccessToken(accessToken);
    }

    String verifySSL = System.getProperty("verifySSL");
    if (verifySSL != null) {
      builder.setVerifySSLCert(Boolean.valueOf(verifySSL));
    }

    builder.setDefaultConnectTimeout(120000);
    builder.setDefaultReadTimeout(120000);
    builder.setUploadConnectTimeout(0);
    builder.setUploadReadTimeout(0);

    return builder.build();
  }

  /**
   * Uses BasicAuthenticationClient to fetch {@link AccessToken}.
   *
   * @param username username to use while connecting
   * @param password password for the above given username
   * @return {@link AccessToken} for the user if authentication is successful
   */
  private AccessToken fetchAccessToken(String username, String password) throws IOException, TimeoutException,
    InterruptedException {
    Properties properties = new Properties();
    properties.setProperty("security.auth.client.username", username);
    properties.setProperty("security.auth.client.password", password);
    final AuthenticationClient authClient = new BasicAuthenticationClient();
    authClient.configure(properties);
    ConnectionConfig connectionConfig = getClientConfig().getConnectionConfig();
    authClient.setConnectionInfo(connectionConfig.getHostname(), connectionConfig.getPort(), false);
    checkServicesWithRetry(new Callable<Boolean>() {
      @Override
      public Boolean call() throws Exception {
        return authClient.getAccessToken() != null;
      }
    }, "Unable to connect to CDAP Authentication service to obtain access token, Connection info : " +
                             connectionConfig);
    return authClient.getAccessToken();
  }

  /**
   * Checks for system services to be up for SERVICE_TIMEOUT_SECONDS with 1 second delay during checks
   */
  private void checkServicesWithRetry(Callable<Boolean> callable,
                                      String exceptionMessage) throws TimeoutException, InterruptedException {
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
    throw new TimeoutException(exceptionMessage);
  }
}
