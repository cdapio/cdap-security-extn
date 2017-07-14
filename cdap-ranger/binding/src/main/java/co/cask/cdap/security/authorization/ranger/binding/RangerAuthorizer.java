package co.cask.cdap.security.authorization.ranger.binding;

import co.cask.cdap.proto.element.EntityType;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.InstanceId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.apache.ranger.plugin.util.GrantRevokeRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Created by rsinha on 4/16/17.
 */
public class RangerAuthorizer extends AbstractAuthorizer {
  private static final Logger LOG = LoggerFactory.getLogger(RangerAuthorizer.class);

  private static final String RANGER_HOST = "ranger.host";
  private static final String RANGER_PORT = "ranger.port";

  public static final String KEY_INSTANCE = "instance";
  public static final String KEY_NAMESPACE = "namespace";

  public static final String ACCESS_TYPE_READ = "read";
  public static final String ACCESS_TYPE_WRITE = "write";
  public static final String ACCESS_TYPE_EXECUTE = "execute";
  public static final String ACCESS_TYPE_ADMIN = "admin";


  private String  rangerHost;
  private String rangerPort;

  private static volatile RangerBasePlugin rangerPlugin = null;
  private AuthorizationContext context;
  long lastLogTime = 0;
  int errorLogFreq = 30000; // Log after every 30 second


  /**
   * @param action
   * @return
   */
  private String mapToRangerAccessType(Action action) {
    switch (action) {
      case READ:
        return ACCESS_TYPE_READ;
      case WRITE:
        return ACCESS_TYPE_WRITE;
      case EXECUTE:
        return ACCESS_TYPE_EXECUTE;
      case ADMIN:
        return ACCESS_TYPE_ADMIN;
      default:
        return null;
    }
  }

  @Override
  public void initialize(AuthorizationContext context) throws Exception {
    System.out.println("#### calling initialize");
////    Properties properties = context.getExtensionProperties();
////    rangerHost = properties.getProperty(RANGER_HOST);
////    rangerHost = properties.getProperty(RANGER_PORT);
////    if (Strings.isNullOrEmpty(rangerHost) || Strings.isNullOrEmpty(rangerPort)) {
////      throw new IllegalArgumentException("Ranger host and port must be provided");
////    }
//
//    if (rangerPlugin == null) {
//
//      try {
//        UserGroupInformation ugi = UserGroupInformation.getLoginUser();
//        if (ugi != null) {
//          MiscUtil.setUGILoginUser(ugi, null);
//        }
//        LOG.info("LoginUser=" + MiscUtil.getUGILoginUser());
//      } catch (Throwable t) {
//        LOG.error("Error getting principal.", t);
//      }
//      MiscUtil.
//
//      rangerPlugin = new RangerBasePlugin("cdap", "cdap");
//      LOG.info("Calling plugin.init()");
//      rangerPlugin.init();
//
//      RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
//      rangerPlugin.setResultProcessor(auditHandler);
//    }
    this.context = context;

    RangerBasePlugin me = rangerPlugin;
    if (me == null) {
      synchronized (RangerAuthorizer.class) {
        me = rangerPlugin;
        if (me == null) {
          try {
            UserGroupInformation ugi = UserGroupInformation.getLoginUser();
            if (ugi != null) {
              MiscUtil.setUGILoginUser(ugi, null);
            }
            LOG.info("LoginUser=" + MiscUtil.getUGILoginUser());
          } catch (Throwable t) {
            LOG.error("Error getting principal.", t);
          }
          rangerPlugin = new RangerBasePlugin("cdap", "cdap");
        }
      }
    }
    LOG.info("Calling plugin.init()");
    rangerPlugin.init();
    RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
    rangerPlugin.setResultProcessor(auditHandler);
  }


  @Override
  public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
    System.out.println("## enforce not supported");
    if (rangerPlugin == null) {
      LOG.info("Authorizer is still not initialized");
      throw new RuntimeException("Authorizer is stil not initialized");
    }

    String userName = getRequestingUser();
    String ip = InetAddress.getLocalHost().getHostName();
    java.util.Set<String> userGroups = MiscUtil
      .getGroupsForRequestUser(userName);
    System.out.println("### The group for this user is: " + userGroups);

    Date eventTime = new Date();
    String accessType = mapToRangerAccessType(action);

    boolean validationFailed = false;
    String validationStr = "";

    if (accessType == null) {
      LOG.warn("Unsupported access type. entity=" + entity
                 + ", principal=" + principal + ", action=" + action);
      validationFailed = true;
      validationStr += "Unsupported access type. action=" + action;
    }

    RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl();
    rangerRequest.setUser(userName);
    rangerRequest.setUserGroups(userGroups);
    rangerRequest.setClientIPAddress(ip);
    rangerRequest.setAccessTime(eventTime);

    RangerAccessResourceImpl rangerResource = new RangerAccessResourceImpl();
    rangerRequest.setResource(rangerResource);
    rangerRequest.setAccessType(accessType);
    rangerRequest.setAction(accessType);
    rangerRequest.setRequestData(entity.toString());

    if (entity.getEntityType() == EntityType.INSTANCE) {
      rangerResource.setValue(KEY_INSTANCE, ((InstanceId) entity).getInstance());
    } else if (entity.getEntityType() == EntityType.NAMESPACE) {
      rangerResource.setValue(KEY_INSTANCE, "cdap");
      rangerResource.setValue(KEY_NAMESPACE, ((NamespaceId) entity).getNamespace());
    } else {
      LOG.warn("Unsupported resourceType=" + entity.getEntityType());
      validationFailed = true;
    }


    boolean returnValue = true;
    if (validationFailed) {
      LOG.warn("Validation failed request=" + rangerRequest);
      returnValue = false;
    } else {
      try {
        RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
        if (result == null) {
          LOG.error("Ranger Plugin returned null. Returning false");
          returnValue = false;
        } else {
          returnValue = result.getIsAllowed();
        }
      } catch (Throwable t) {
        LOG.error("Error while calling isAccessAllowed(). request="
                       + rangerRequest, t);
        throw t;
      } finally {
        if (LOG.isDebugEnabled()) {
          LOG.debug("rangerRequest=" + rangerRequest + ", return="
                         + returnValue);
        }
      }
    }
    if (!returnValue) {
      throw new UnauthorizedException(principal, action, entity);
    }
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> set) throws Exception {
    boolean flag = false;
    for (Action action : set) {
        enforce(entityId, principal, action);
    }
  }

  @Override
  public void grant(EntityId entity, Principal principal, java.util.Set<Action> actions) throws Exception {
    LOG.warn("Grant Operation not supported by Ranger for CDAP");
  }

  @Override
  public void revoke(EntityId entity, Principal principal, java.util.Set<Action> actions) throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void revoke(EntityId entity) throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void createRole(Role role) throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");

  }

  @Override
  public void dropRole(Role role) throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");

  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");

  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");

  }

  @Override
  public Set<Role> listRoles(Principal principal) throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");
    return null;
  }

  @Override
  public Set<Role> listAllRoles() throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");
    return null;
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    LOG.warn("Operation not supported by Ranger for CDAP");
    return null;
  }

  private String getRequestingUser() throws IllegalArgumentException {
    Principal principal = context.getPrincipal();
    LOG.trace("Got requesting principal {}", principal);
    return principal.getName();
  }

}
