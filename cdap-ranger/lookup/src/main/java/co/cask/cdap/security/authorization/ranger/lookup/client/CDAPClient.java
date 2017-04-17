package co.cask.cdap.security.authorization.ranger.lookup.client;

import co.cask.cdap.cli.util.InstanceURIParser;
import co.cask.cdap.client.NamespaceClient;
import co.cask.cdap.client.config.ClientConfig;
import co.cask.cdap.client.config.ConnectionConfig;
import co.cask.cdap.proto.NamespaceMeta;
import co.cask.cdap.security.authentication.client.AccessToken;
import co.cask.cdap.security.authentication.client.AuthenticationClient;
import co.cask.cdap.security.authentication.client.basic.BasicAuthenticationClient;
import com.google.common.base.Throwables;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.client.BaseClient;
import org.apache.ranger.plugin.service.ResourceLookupContext;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * CDAPClient
 */
public class CDAPClient {

  private static final Log LOG = LogFactory.getLog(CDAPClient.class);
  private static final long SERVICE_CHECK_TIMEOUT_SECONDS = TimeUnit.MINUTES.toSeconds(30);
  private AccessToken accessToken;
  private final String serviceName;
  private final String instanceURL;
  private final String username;
  private final String password;
  private final NamespaceClient nsClient;
  public static final String ERR_MSG = " You can still save the repository and start creating "
    + "policies, but you would not be able to use autocomplete for "
    + "resource names. Check xa_portal.log for more info.";

  public CDAPClient(String serviceName, String instanceURL, String username, String password) {
    this.serviceName = serviceName;
    this.instanceURL = instanceURL;
    this.username = username;
    this.password = password;
    initConnection();
    this.nsClient = new NamespaceClient(getClientConfig());
  }


  private void initConnection() {
    if (username != null && password != null) {
      // security is enabled, we need to get access token before checking system services
      try {
        LOG.info("### Fetching access token with username:" + username + " passsword: " + password);
        accessToken = fetchAccessToken(username, password);
      } catch (Exception ex) {
        throw Throwables.propagate(ex);
      }
    }
  }

  private List<String> getNamespaceList(String nsMatching, List<String> nsList) throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> CDAPClient getDBList databaseMatching : " + nsMatching + " ExcludedbList :" + nsList);
    }

    List<String> ret = new ArrayList<>();
    if (nsClient != null) {
      for (NamespaceMeta namespaceMeta : nsClient.list()) {
        String name = namespaceMeta.getName();
        if (!name.startsWith(nsMatching) && !nsList.contains(name)) {
          continue;
        }
        ret.add(name);
      }
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("<== CDApClient.getDBList(): " + ret);
    }

    return ret;
  }

  public List<String> getNamespaces(final String nsMatching, final List<String> namespaces) {

    try {
      return getNamespaceList(nsMatching, namespaces);
    } catch (Exception he) {
      LOG.error("<== HiveClient getDatabaseList() :Unable to get the Database List and access token was: " +
                  accessToken, he);
      throw Throwables.propagate(he);
    }
  }

  public HashMap<String, Object> connectionTest() throws Exception {
    HashMap<String, Object> responseData = new HashMap<>();
    boolean connectivityStatus = false;
    List<String> testResult;
    try {
      testResult = getNamespaces("", null);
      if (testResult != null && testResult.size() != 0) {
        connectivityStatus = true;
      }
      if (connectivityStatus) {
        String successMsg = "ConnectionTest Successful";
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
    return responseData;
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

    LOG.info("##### Yooooo here ####");
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
    } while (System.currentTimeMillis() <= startingTime + SERVICE_CHECK_TIMEOUT_SECONDS * 1000);

    // when we have passed the timeout and the check for services is not successful
    throw new TimeoutException(exceptionMessage);
  }

  public List<String> getResources(ResourceLookupContext context) {
    return new ArrayList<>();
  }
}
