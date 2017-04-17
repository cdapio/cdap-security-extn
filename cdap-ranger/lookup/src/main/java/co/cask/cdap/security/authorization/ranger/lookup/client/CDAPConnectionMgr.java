package co.cask.cdap.security.authorization.ranger.lookup.client;

import com.google.common.base.Strings;

import java.util.Map;

/**
 * Connection cache
 */
public class CDAPConnectionMgr {

  private static final String INSTANCE_URL = "instance.url";
  private static final String USERNAME = "username";
  private static final String PASSWORD = "password";


  public static CDAPClient getCDAPClient(String serviceName, Map<String, String> configs) throws Exception {

    String instanceURL = configs.get(INSTANCE_URL);
    String username = configs.get(USERNAME);
    String password = configs.get(PASSWORD);
    if (!(Strings.isNullOrEmpty(instanceURL) || Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(password))) {
      return new CDAPClient(serviceName, instanceURL, username, password);
    }
    throw new Exception("Required properties are not set for "
                          + serviceName + ". CDAP instance url with port, username and password must be provided.");


  }

  public static Map<String, Object> testConnection(String serviceName, Map<String, String> configs) throws Exception {
    CDAPClient serviceSolrClient = getCDAPClient(serviceName, configs);
    return serviceSolrClient.connectionTest();
  }
}
