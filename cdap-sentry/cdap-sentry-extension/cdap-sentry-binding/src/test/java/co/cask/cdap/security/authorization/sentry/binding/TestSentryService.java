package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import com.google.common.base.Joiner;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.sentry.binding.hive.SentryIniPolicyFileFormatter;
import org.apache.sentry.binding.hive.SentryPolicyFileFormatFactory;
import org.apache.sentry.binding.hive.SentryPolicyFileFormatter;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClient;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClientFactory;
import org.apache.sentry.provider.db.service.thrift.PolicyStoreConstants;
import org.apache.sentry.provider.db.service.thrift.SentryPolicyServiceClient;
import org.apache.sentry.provider.file.LocalGroupResourceAuthorizationProvider;
import org.apache.sentry.service.thrift.SentryService;
import org.apache.sentry.service.thrift.SentryServiceClientFactory;
import org.apache.sentry.service.thrift.SentryServiceFactory;
import org.apache.sentry.service.thrift.ServiceConstants;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 *
 */
public class TestSentryService {

  private final File tempDir;
  private final File policyFile;
  private SentryService sentryServer;

  public TestSentryService(File tempDir, File policyFile) {
    this.tempDir = tempDir;
    this.policyFile = policyFile;
  }

  public void start() throws Exception {
    File dbDir = new File(tempDir, "sentry_policy_db");
    Configuration conf = new Configuration();

    conf.set(ServiceConstants.ServerConfig.SECURITY_MODE, ServiceConstants.ServerConfig.SECURITY_MODE_NONE);
    conf.set(ServiceConstants.ServerConfig.SENTRY_VERIFY_SCHEM_VERSION, "false");
    conf.set(ServiceConstants.ServerConfig.RPC_PORT, String.valueOf(getRandomPort()));
    conf.set(ServiceConstants.ServerConfig.RPC_ADDRESS, NetUtils.createSocketAddr(
      InetAddress.getLocalHost().getHostAddress() + ":" + conf.get(ServiceConstants.ServerConfig.RPC_PORT))
      .getAddress().getCanonicalHostName());
    conf.set(ServiceConstants.ServerConfig.SENTRY_STORE_JDBC_URL,
             "jdbc:derby:;databaseName=" + dbDir.getPath() + ";create=true");
    conf.set(ServiceConstants.ServerConfig.SENTRY_STORE_JDBC_PASS, "dummy");
    conf.set(ServiceConstants.ServerConfig.SENTRY_STORE_GROUP_MAPPING,
             ServiceConstants.ServerConfig.SENTRY_STORE_LOCAL_GROUP_MAPPING);
    conf.set(ServiceConstants.ServerConfig.SENTRY_STORE_GROUP_MAPPING_RESOURCE,
             policyFile.getPath());
    conf.set(ServiceConstants.ServerConfig.ADMIN_GROUPS, "cdap");

    sentryServer = new SentryServiceFactory().create(conf);
    sentryServer.start();
    final long start = System.currentTimeMillis();
    while(!sentryServer.isRunning()) {
      TimeUnit.MILLISECONDS.sleep(50);
      if(System.currentTimeMillis() - start > 60000L) {
        throw new TimeoutException("Server did not start after 60 seconds");
      }
    }
    importPolicy();
  }

  public void stop() throws Exception {
    if (sentryServer != null) {
      sentryServer.stop();
    }
  }

  public Configuration getClientConfig() {
    Configuration conf = new Configuration();
    /** set the Sentry client configuration for Kafka Service integration */
    conf.set(ServiceConstants.ServerConfig.SECURITY_MODE, ServiceConstants.ServerConfig.SECURITY_MODE_NONE);
    conf.set(ServiceConstants.ClientConfig.SERVER_RPC_ADDRESS, sentryServer.getAddress().getHostName());
    conf.set(ServiceConstants.ClientConfig.SERVER_RPC_PORT, String.valueOf(sentryServer.getAddress().getPort()));

    conf.set(AuthConf.AuthzConfVars.AUTHZ_PROVIDER.getVar(),
             LocalGroupResourceAuthorizationProvider.class.getName());
    conf.set(AuthConf.AuthzConfVars.AUTHZ_PROVIDER_BACKEND.getVar(),
             SentryGenericProviderBackend.class.getName());
    conf.set(AuthConf.AuthzConfVars.AUTHZ_PROVIDER_RESOURCE.getVar(), policyFile.getAbsolutePath());
    return conf;
  }

  private void importPolicy() throws Exception {
    SentryIniPolicyFileFormatter policyFileFormatter = new SentryIniPolicyFileFormatter();
    Map<String, Map<String, Set<String>>> policyMap =
      policyFileFormatter.parse(policyFile.getAbsolutePath(), new Configuration());
    SentryGenericServiceClient serviceClient = SentryGenericServiceClientFactory.create(getClientConfig());


//    SentryPolicyServiceClient client = SentryServiceClientFactory.create(getClientConfig());
//    // import the mapping data to database
//    client.importPolicy(policyMap, "cdap", true);
  }

  /**
   * Find a random free port in localhost for binding.
   * @return A port number or -1 for failure.
   */
  public static int getRandomPort() {
    try {
      try (ServerSocket socket = new ServerSocket(0)) {
        return socket.getLocalPort();
      }
    } catch (IOException e) {
      return -1;
    }
  }

}
