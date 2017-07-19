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
package co.cask.cdap.security.authorization.ranger.lookup;

import co.cask.cdap.security.authorization.ranger.lookup.client.CDAPClient;
import co.cask.cdap.security.authorization.ranger.lookup.client.CDAPConnectionMgr;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.client.HadoopException;
import org.apache.ranger.plugin.model.RangerService;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.service.RangerBaseService;
import org.apache.ranger.plugin.service.ResourceLookupContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 * CDAP Resource Lookup Service
 * Note: The log statements in this class are written in a formatted way to match the logging format
 * used by other services in Apache Ranger since these log statements end up in ranger admin log file we
 * want them to be in same format.
 */
public class RangerLookupService extends RangerBaseService {
  private static final Log LOG = LogFactory.getLog(RangerLookupService.class);

  public RangerLookupService() {
    super();
  }

  @Override
  public void init(RangerServiceDef serviceDef, RangerService service) {
    super.init(serviceDef, service);
  }

  @Override
  public HashMap<String, Object> validateConfig() throws Exception {
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> RangerLookupService.validateConfig(" + serviceName + ")");
    }

    // HashMap since validateConfig api returns a HashMap.
    HashMap<String, Object> response = new HashMap<>();
    if (configs != null) {
      try {
        response.putAll(CDAPConnectionMgr.testConnection(serviceName, configs));
      } catch (HadoopException e) {
        LOG.error("<== RangerLookupService.validateConfig Error:" + e);
        throw e;
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("<== RangerLookupService.validateConfig(" + serviceName + ")");
    }
    return response;
  }

  @Override
  public List<String> lookupResource(ResourceLookupContext context) throws Exception {
    List<String> ret = null;
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> RangerLookupService.lookupResource Context: (" + context + ")");
    }
    if (context != null) {
      try {
        CDAPClient client = CDAPConnectionMgr.getCDAPClient(serviceName, configs);
        // TODO do resource lookup here
      } catch (Exception e) {
        LOG.error("<== RangerServiceHive.lookupResource Error : " + e);
        throw e;
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("<== RangerLookupService.lookupResource Response: (" + ret + ")");
    }
    return Collections.emptyList();
  }
}
