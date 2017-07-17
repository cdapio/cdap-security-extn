package co.cask.cdap.security.authorization.ranger.lookup.client;

import com.google.common.base.Strings;

import java.util.Map;

/**
 * CDAP Client and Connection Manager.
 */
public class CDAPConnectionMgr {

  private static final String INSTANCE_URL = "cdap.instance.url";
  private static final String USERNAME = "cdap.username";
  private static final String PASSWORD = "cdap.password";

  /**
   * Returns a CDAP Client containing namespace, stream, dataset etc clients
   * @param serviceName the name of the service e.g. cdap
   * @param configs configs to use to create the cdap clients.
   * @return {@link CDAPClient}
   */
  public static CDAPClient getCDAPClient(String serviceName, Map<String, String> configs) throws Exception {
    String instanceURL = configs.get(INSTANCE_URL);
    String username = configs.get(USERNAME);
    String password = configs.get(PASSWORD);
    if (!(Strings.isNullOrEmpty(instanceURL) || Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password))) {
      return new CDAPClient(serviceName, instanceURL, username, password);
    }
    throw new IllegalArgumentException("Required properties are not set for "
                          + serviceName + ". CDAP instance url with port, username and password must be provided.");
  }

  /**
   * Tests that connection to CDAP instance can be made with the given config
   * @param serviceName the name of the service
   * @param configs the configs for the connection
   */
  public static void testConnection(String serviceName, Map<String, String> configs) throws Exception {
    CDAPClient cdapClient = getCDAPClient(serviceName, configs);
    cdapClient.testConnection();
  }
}
