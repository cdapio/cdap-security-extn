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

package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.security.authorization.sentry.binding.conf.AuthConf;
import co.cask.cdap.security.authorization.sentry.model.Authorizable;
import co.cask.cdap.security.authorization.sentry.policy.ModelAuthorizables;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.net.NetUtils;
import org.apache.sentry.binding.hive.SentryIniPolicyFileFormatter;
import org.apache.sentry.provider.db.generic.SentryGenericProviderBackend;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClient;
import org.apache.sentry.provider.db.generic.service.thrift.SentryGenericServiceClientFactory;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;
import org.apache.sentry.provider.file.LocalGroupResourceAuthorizationProvider;
import org.apache.sentry.service.thrift.SentryService;
import org.apache.sentry.service.thrift.SentryServiceFactory;
import org.apache.sentry.service.thrift.ServiceConstants;
import org.junit.Assert;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Utility class for starting, setting up, and stopping Sentry.
 */
class TestSentryService {

  static final String ADMIN_USER = "cdap";
  private static final String COMPONENT = "cdap";

  private final File tempDir;
  private final File policyFile;
  private SentryService sentryServer;

  TestSentryService(File tempDir, File policyFile) {
    this.tempDir = tempDir;
    this.policyFile = policyFile;
  }

  void start() throws Exception {
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
    conf.set("sentry.cdap.action.factory", "co.cask.cdap.security.authorization.sentry.model.ActionFactory");

    sentryServer = new SentryServiceFactory().create(conf);
    sentryServer.start();
    final long start = System.currentTimeMillis();
    while (!sentryServer.isRunning()) {
      TimeUnit.MILLISECONDS.sleep(50);
      if (System.currentTimeMillis() - start > 60000L) {
        throw new TimeoutException("Server did not start after 60 seconds");
      }
    }

    SentryGenericServiceClient sentryClient = SentryGenericServiceClientFactory.create(getClientConfig());
    try {
      importPolicy(sentryClient);
    } finally {
      sentryClient.close();
    }
  }

  void stop() throws Exception {
    if (sentryServer != null) {
      sentryServer.stop();
    }
  }

  Configuration getClientConfig() {
    Configuration conf = new Configuration();
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

  private void importPolicy(SentryGenericServiceClient sentryClient) throws Exception {
    SentryIniPolicyFileFormatter policyFileFormatter = new SentryIniPolicyFileFormatter();
    Map<String, Map<String, Set<String>>> policyMap =
      policyFileFormatter.parse(policyFile.getAbsolutePath(), new Configuration());

    Map<String, Set<String>> groups = policyMap.get("groups");
    Map<String, Set<String>> roles = policyMap.get("roles");

    for (Map.Entry<String, Set<String>> groupEntry : groups.entrySet()) {
      String group = groupEntry.getKey();
      for (String role : groupEntry.getValue()) {
        addRoleToGroup(sentryClient, role, group);
      }
    }

    for (Map.Entry<String, Set<String>> roleEntry : roles.entrySet()) {
      String role = roleEntry.getKey();
      Set<String> privileges = roleEntry.getValue();
      for (String privilege : privileges) {
        // instance=cdap->namespace=ns1->dataset=ds1->action=read
        Map<String, String> parsedPrivilege = Splitter.on("->").withKeyValueSeparator("=").split(privilege);

        List<Map.Entry<String, String>> privilegeParts = Lists.newArrayList(parsedPrivilege.entrySet().iterator());
        Map.Entry<String, String> instancePart = privilegeParts.get(0);
        Assert.assertEquals("instance", instancePart.getKey());
        String instance = instancePart.getValue();

        Map.Entry<String, String> actionPart = privilegeParts.get(privilegeParts.size() - 1);
        Assert.assertEquals("action", actionPart.getKey());
        String action = actionPart.getValue();

        // remove the action
        privilegeParts = privilegeParts.subList(0, privilegeParts.size() - 1);

        List<Authorizable> authorizables = new ArrayList<>();
        for (Map.Entry<String, String> privilegePart : privilegeParts) {
          authorizables.add(ModelAuthorizables.from(privilegePart.getKey(), privilegePart.getValue()));
        }

        addPermissions(sentryClient, role, action, instance, toTAuthorizables(authorizables));
      }
    }
  }

  private void addRoleToGroup(SentryGenericServiceClient sentryClient, String role, String group) throws Exception {
    sentryClient.createRoleIfNotExist(ADMIN_USER, role, COMPONENT);
    sentryClient.addRoleToGroups(ADMIN_USER, role, COMPONENT, Sets.newHashSet(group));
  }

  private void addPermissions(SentryGenericServiceClient sentryClient, String role, String action, String instance,
                              ArrayList<TAuthorizable> authorizables) throws Exception {
    sentryClient.grantPrivilege(ADMIN_USER, role, COMPONENT,
                                new TSentryPrivilege(COMPONENT, instance, authorizables, action));
  }

  private ArrayList<TAuthorizable> toTAuthorizables(List<Authorizable> authorizables) {
    ArrayList<TAuthorizable> tAuthorizables = new ArrayList<>(authorizables.size());
    for (Authorizable authorizable : authorizables) {
      tAuthorizables.add(new TAuthorizable(authorizable.getTypeName(), authorizable.getName()));
    }
    return tAuthorizables;
  }

  /**
   * Find a random free port in localhost for binding.
   * @return A port number or -1 for failure.
   */
  private static int getRandomPort() {
    try {
      try (ServerSocket socket = new ServerSocket(0)) {
        return socket.getLocalPort();
      }
    } catch (IOException e) {
      return -1;
    }
  }
}
