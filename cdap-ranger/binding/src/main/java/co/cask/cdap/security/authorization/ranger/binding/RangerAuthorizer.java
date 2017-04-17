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
import javax.security.auth.Subject;

/**
 * Created by rsinha on 4/16/17.
 */
public class RangerAuthorizer extends AbstractAuthorizer {
  private static final Logger LOG = LoggerFactory.getLogger(RangerAuthorizer.class);

  public static final String KEY_INSTANCE = "instance";
  public static final String KEY_NAMESPACE = "namespace";

  public static final String ACCESS_TYPE_READ = "read";
  public static final String ACCESS_TYPE_WRITE = "write";
  public static final String ACCESS_TYPE_EXECUTE = "execute";
  public static final String ACCESS_TYPE_ADMIN = "admin";

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
    if (rangerPlugin == null) {

      try {
        Subject subject = new Subject();
        UserGroupInformation ugi = MiscUtil
          .createUGIFromSubject(subject);
        if (ugi != null) {
          MiscUtil.setUGILoginUser(ugi, subject);
        }
        LOG.info("LoginUser=" + MiscUtil.getUGILoginUser());
      } catch (Throwable t) {
        LOG.error("Error getting principal.", t);
      }

      rangerPlugin = new RangerBasePlugin("cdap", "cdap");
      LOG.info("Calling plugin.init()");
      rangerPlugin.init();

      RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
      rangerPlugin.setResultProcessor(auditHandler);
    }
    this.context = context;
  }


  @Override
  public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
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

    if (entity.getEntity() == EntityType.INSTANCE) {
      rangerResource.setValue(KEY_INSTANCE, ((InstanceId) entity).getInstance());
    } else if (entity.getEntity() == EntityType.NAMESPACE) {
      rangerResource.setValue(KEY_INSTANCE, "cdap");
      rangerResource.setValue(KEY_NAMESPACE, ((NamespaceId) entity).getNamespace());
    } else {
      LOG.warn("Unsupported resourceType=" + entity.getEntity());
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

  }

  @Override
  public void grant(EntityId entity, Principal principal, java.util.Set<Action> actions) throws Exception {
    RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();

    try {
      GrantRevokeRequest ret = new GrantRevokeRequest();

      ret.setGrantor(getRequestingUser());
      ret.setDelegateAdmin(Boolean.FALSE);
      ret.setEnableAudit(Boolean.TRUE);
      ret.setReplaceExistingPermissions(Boolean.FALSE);

      String instance = null;
      String namespace = null;
      if (entity.getEntity() == EntityType.INSTANCE) {
        instance = ((InstanceId) entity).getInstance();
        namespace = "*";
      } else if (entity.getEntity() == EntityType.NAMESPACE) {
        instance = "cdap";
        namespace = ((NamespaceId) entity).getNamespace();
      } else {
        LOG.warn("Unsupported Entity=" + entity.getEntity());
      }
      Map<String, String> mapResource = new HashMap<String, String>();
      mapResource.put(KEY_INSTANCE, instance);
      mapResource.put(KEY_NAMESPACE, namespace);

      ret.setResource(mapResource);

      switch (principal.getType()) {
        case USER:
          ret.getUsers().add(principal.getName());
          break;

        case GROUP:
        case ROLE:
          ret.getGroups().add(principal.getName());
          break;
        default:
          throw new RuntimeException("unknown principal");
      }


      for (Action action : actions) {
        ret.getAccessTypes().add(mapToRangerAccessType(action));
      }


      LOG.info("grantPrivileges(): " + ret);
      if (LOG.isDebugEnabled()) {
        LOG.debug("grantPrivileges(): " + ret);
      }


      rangerPlugin.grantAccess(ret, auditHandler);
    } catch (Exception excp) {
      throw new RuntimeException(excp);
    }
  }

  @Override
  public void revoke(EntityId entity, Principal principal, java.util.Set<Action> actions) throws Exception {
    LOG.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void revoke(EntityId entity) throws Exception {
    LOG.error("Operation not supported by Ranger for CDAP");
  }

  @Override
  public void createRole(Role role) throws Exception {

  }

  @Override
  public void dropRole(Role role) throws Exception {

  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {

  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {

  }

  @Override
  public Set<Role> listRoles(Principal principal) throws Exception {
    return null;
  }

  @Override
  public Set<Role> listAllRoles() throws Exception {
    return null;
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    return null;
  }

  private String getRequestingUser() throws IllegalArgumentException {
    Principal principal = context.getPrincipal();
    LOG.trace("Got requesting principal {}", principal);
    return principal.getName();
  }

}
