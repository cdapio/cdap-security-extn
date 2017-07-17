package co.cask.cdap.security.authorization.ranger.lookup;

import co.cask.cdap.security.authorization.ranger.lookup.client.CDAPClient;
import co.cask.cdap.security.authorization.ranger.lookup.client.CDAPConnectionMgr;
import com.google.common.collect.Maps;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ranger.plugin.client.HadoopException;
import org.apache.ranger.plugin.model.RangerService;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.service.RangerBaseService;
import org.apache.ranger.plugin.service.ResourceLookupContext;

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

    if (configs != null) {
      try {
        CDAPConnectionMgr.testConnection(serviceName, configs);
      } catch (HadoopException e) {
        LOG.error("<== RangerServiceCDAP.validateConfig Error:" + e);
        throw e;
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("<== RangerLookupService.validateConfig(" + serviceName + ")");
    }
    return Maps.newHashMap();
  }

  @Override
  public List<String> lookupResource(ResourceLookupContext context) throws Exception {
    List<String> ret = null;
    if (LOG.isDebugEnabled()) {
      LOG.debug("==> RangerLookupService.lookupResource Context: (" + context + ")");
    }
    if (context != null) {
      try {
        CDAPClient cdapClient = CDAPConnectionMgr.getCDAPClient(serviceName, configs);
        ret = cdapClient.getResources(context);
      } catch (Exception e) {
        LOG.error("<==RangerServiceHive.lookupResource Error : " + e);
        throw e;
      }
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("<== RangerServiceHive.lookupResource Response: (" + ret + ")");
    }
    return ret;
  }
}
