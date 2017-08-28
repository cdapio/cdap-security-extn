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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.ranger.admin.client.RangerAdminClient;
import org.apache.ranger.plugin.util.GrantRevokeRequest;
import org.apache.ranger.plugin.util.ServicePolicies;
import org.apache.ranger.plugin.util.ServiceTags;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * A test implementation of the RangerAdminClient interface that just reads policies in from a file and returns them.
 * Note: This code is taken from Apache Ranger
 * https://github.com/apache/ranger/blob/master/hdfs-agent/src/test/java/org/apache/ranger
 * /services/hdfs/RangerAdminClientImpl.java
 */
public class RangerAdminClientImpl implements RangerAdminClient {
  private static final Logger LOG = LoggerFactory.getLogger(RangerAdminClientImpl.class);
  private static final String CDAP_POLICIES_JSON = "cdap-policies.json";
  private Gson gson;

  public void init(String serviceName, String appId, String configPropertyPrefix) {
    Gson gson = null;
    try {
      gson = new GsonBuilder().setDateFormat("yyyyMMdd-HH:mm:ss.SSS-Z").setPrettyPrinting().create();
    } catch (Throwable t) {
      LOG.error("RangerAdminClientImpl: failed to create GsonBuilder object", t);
    }
    this.gson = gson;
  }

  public ServicePolicies getServicePoliciesIfUpdated(long lastKnownVersion,
                                                     long lastActivationTimeInMillis) throws Exception {
    String basedir = System.getProperty("basedir");
    if (basedir == null) {
      basedir = new File(".").getCanonicalPath();
    }
    Path cachePath = FileSystems.getDefault().getPath(basedir, "/src/test/resources/" + CDAP_POLICIES_JSON);
    byte[] cacheBytes = Files.readAllBytes(cachePath);
    return gson.fromJson(new String(cacheBytes), ServicePolicies.class);
  }

  public void grantAccess(GrantRevokeRequest request) throws Exception {
    // no-op
  }

  public void revokeAccess(GrantRevokeRequest request) throws Exception {
    // no-op
  }

  public ServiceTags getServiceTagsIfUpdated(long lastKnownVersion, long lastActivationTimeInMillis) throws Exception {
    // cdap does not support tag based authorization at this point
    return new ServiceTags();
  }

  public List<String> getTagTypes(String tagTypePattern) throws Exception {
    return null;
  }
}
