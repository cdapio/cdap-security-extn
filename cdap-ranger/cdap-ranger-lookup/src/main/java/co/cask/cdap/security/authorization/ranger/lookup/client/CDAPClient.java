package co.cask.cdap.security.authorization.ranger.lookup.client;

import co.cask.cdap.cli.util.InstanceURIParser;
import co.cask.cdap.client.NamespaceClient;
import co.cask.cdap.client.StreamClient;
import co.cask.cdap.client.config.ClientConfig;
import co.cask.cdap.client.config.ConnectionConfig;
import co.cask.cdap.proto.NamespaceMeta;
import co.cask.cdap.proto.StreamDetail;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.security.authentication.client.AccessToken;
import co.cask.cdap.security.authentication.client.AuthenticationClient;
import co.cask.cdap.security.authentication.client.basic.BasicAuthenticationClient;
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

/**
 * CDAP Clients which to be used by ranger for listing cdap resources.
 */
public class CDAPClient {

  private static final Log LOG = LogFactory.getLog(CDAPClient.class);
  private static final long SERVICE_TIMEOUT_SECONDS = TimeUnit.MINUTES.toSeconds(30);
  private enum ResourceType {
    INSTANCE, NAMESPACE, DATASET, STREAM, APPLICATION, ARTIFACT, PROGRAM
  }
  private static final String INSTANCE = "instance";
  private static final String NAMESPACE = "namespace";
  private static final String STREAM = "stream";
  private AccessToken accessToken;
  private final String serviceName;
  private final String instanceURL;
  private final String username;
  private final String password;
  private final NamespaceClient nsClient;
  private static final String ERR_MSG = " You can still save the repository and start creating "
    + "policies, but you would not be able to use autocomplete for "
    + "resource names. Check xa_portal.log for more info.";
  private final StreamClient streamClient;

  CDAPClient(String serviceName, String instanceURL, String username, String password) {
    this.serviceName = serviceName;
    this.instanceURL = instanceURL;
    this.username = username;
    this.password = password;
    initConnection();
    ClientConfig clientConfig = getClientConfig();
    this.nsClient = new NamespaceClient(clientConfig);
    this.streamClient = new StreamClient(clientConfig);
  }

  private void initConnection() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPClient initConnection()");
    }
    if (username != null && password != null) {
      // security is enabled, we need to get access token before checking system services
      try {
        LOG.debug(String.format("Fetching access token with username %s and password ****", username));
        accessToken = fetchAccessToken(username, password);
      } catch (Exception ex) {
        throw Throwables.propagate(ex);
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPClient initConnection()");
    }
  }

  void testConnection() throws Exception {
    HashMap<String, Object> responseData = new HashMap<>();
    List<String> testResult;
    try {
      testResult = getNamespaces(null);
      if (testResult != null && testResult.size() >= 0) {
        String successMsg = "Connection Test Successful";
        BaseClient.generateResponseDataMap(true, successMsg, successMsg,
                                           null, null, responseData);
      } else {
        String failureMsg = "Unable to retrieve any namespace using given parameters. " +
          "Please ensure that the configurations are correct and at least one namespace is accessible to this user.";
        BaseClient.generateResponseDataMap(false, failureMsg, failureMsg + ERR_MSG,
                                           null, null, responseData);
      }
    } catch (Exception e) {
      LOG.error("Error connecting to CDAP.", e);
      String failureMsg = "Unable to connect to CDAP instance." + e.getMessage();
      BaseClient.generateResponseDataMap(false, failureMsg,
                                         failureMsg + ERR_MSG, null, null, responseData);
    }
  }

  private List<String> getNamespaces(List<String> nsList) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPClient getNamespaceList ExcludeNamespaceList :" + nsList);
    }

    List<String> ret = new ArrayList<>();
    if (nsClient != null) {
      for (NamespaceMeta namespaceMeta : nsClient.list()) {
        String name = namespaceMeta.getName();
        if (nsList == null || !nsList.contains(name)) {
          ret.add(name);
        }
      }
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDApClient.getDBList(): " + ret);
    }
    return ret;
  }

  private List<String> getStream(List<String> nsList, NamespaceId namespaceId) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPClient getNamespaceList ExcludeNamespaceList :" + nsList);
    }

    List<String> ret = new ArrayList<>();
    if (nsClient != null) {
      for (StreamDetail streamDetail : streamClient.list(namespaceId)) {

        String name = streamDetail.getName();
        System.out.println("### name is " + name);
        if (nsList == null || !nsList.contains(name)) {
          ret.add(name);
        }
      }
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDApClient.getDBList(): " + ret);
    }
    System.out.println("lis tis " + ret);
    return ret;
  }

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
   * Uses BasicAuthenticationClient to fetch {@link AccessToken} - this implementation can be overridden if desired.
   *
   * @return {@link AccessToken}
   * @throws IOException
   * @throws TimeoutException if a timeout occurs while getting an access token
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

    System.out.println("Usernmae " + username + "password " + password);
    System.out.println("##### Yooooo here ####");

    checkServicesWithRetry(new Callable<Boolean>() {
      @Override
      public Boolean call() throws Exception {
        return authClient.getAccessToken() != null;
      }
    }, "Unable to connect to Authentication service to obtain access token, Connection info : " + connectionConfig);

    return authClient.getAccessToken();
  }

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

  public List<String> getResources(ResourceLookupContext context) {
    final String userInput = context.getUserInput();
    final String resource = context.getResourceName();
    Map<String, List<String>> resourceMap = context.getResources();
    List<String> resultList = null;
    List<String> instanceList = null;
    List<String> namespaceList = null;
    List<String> streamList = null;
    String instanceName = null;
    String namespaceName = null;

    ResourceType lookupResource = ResourceType.INSTANCE;


    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDAPResourceMgr.getResources()  UserInput: \"" + userInput + "\" resource : " + resource +
                  " resourceMap: " + resourceMap);
    }

    if (userInput != null && resource != null) {
      if (resourceMap != null && !resourceMap.isEmpty()) {
        instanceList = resourceMap.get(INSTANCE);
        namespaceList = resourceMap.get(NAMESPACE);
        streamList = resourceMap.get(STREAM);
      }
      System.out.println("Resource trim:" + resource.trim().toLowerCase());
      switch (resource.trim().toLowerCase()) {
        case INSTANCE:
          lookupResource = ResourceType.INSTANCE;
          break;
        case NAMESPACE:
          lookupResource = ResourceType.NAMESPACE;
          System.out.println("#### set the namespace name to : " + userInput);
          break;
        case STREAM:
          lookupResource = ResourceType.STREAM;
          System.out.println("#### set the stream name to : " + userInput);
          break;
        default:
          break;
      }
    }

    if (serviceName != null && userInput != null) {
      try {
//          LOG.info("==> CDAPResourceMgr.getResources() UserInput: " + userInput + " configs: " + configs + " " +
//                      "instanceList: " + instanceList + " namespaceList: " + namespaceList);



        Callable<List<String>> callableObj = null;
        final String userInputFinal = userInput;


        final List<String> finalinstanceList = instanceList;
        final List<String> finalnamespaceList = namespaceList;
        final List<String> finalstreamList = streamList;

          if (lookupResource == ResourceType.NAMESPACE) {
            // get the DBList for given Input
            callableObj = new Callable<List<String>>() {
              @Override
              public List<String> call() {
                List<String> retList = new ArrayList<String>();
                try {
                  List<String> list = getNamespaces(finalnamespaceList);
                  if (userInputFinal != null
                    && !userInputFinal.isEmpty()) {
                    for (String value : list) {
                      if (value.startsWith(userInputFinal)) {
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
          } else if (lookupResource == ResourceType.STREAM) {
            System.out.print("This is a stream lookupResource");
            // get the DBList for given Input
            callableObj = new Callable<List<String>>() {
              @Override
              public List<String> call() {
                List<String> retList = new ArrayList<String>();
                try {
                  String namespaceTemp = finalnamespaceList.get(0);
                  System.out.print("namespaceTemp:" + namespaceTemp);
                  System.out.print("finalnamespaceList:" + finalnamespaceList);
                  LOG.info("aaaaaaaaaaaaaaaaaaaaa" + namespaceTemp);
                  List<String> list = getStream(finalstreamList, new NamespaceId(namespaceTemp));
                  if (userInputFinal != null
                    && !userInputFinal.isEmpty()) {
                    for (String value : list) {
                      if (value.startsWith(userInputFinal)) {
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
          }
          System.out.println("lookupResource " + lookupResource);
          //else ResourceType.STREAM

          if (callableObj != null) {
            synchronized (this) {
              resultList = TimedEventUtil.timedTask(callableObj, SERVICE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            }
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

}
