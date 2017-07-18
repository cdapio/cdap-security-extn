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
import co.cask.cdap.security.spi.authorization.Authorizer;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Date;
import java.util.EnumSet;
import java.util.Set;

/**
 * This class implements {@link Authorizer} from CDAP and is responsible for interacting with Ranger to enforece
 * authorization.
 */
public class RangerAuthorizer extends AbstractAuthorizer {
  private static final Logger LOG = LoggerFactory.getLogger(RangerAuthorizer.class);

  private static final String KEY_INSTANCE = "instance";
  private static final String KEY_NAMESPACE = "namespace";


  private static volatile RangerBasePlugin rangerPlugin = null;
  private AuthorizationContext context;

  @Override
  public synchronized void initialize(AuthorizationContext context) throws Exception {
    this.context = context;
    if (rangerPlugin == null) {
      try {
        UserGroupInformation ugi = UserGroupInformation.getLoginUser();
        if (ugi != null) {
          MiscUtil.setUGILoginUser(ugi, null);
        }
        LOG.debug("Initializing Ranger CDAP Plugin with UGI {}", ugi);
      } catch (Throwable t) {
        LOG.error("Error getting principal.", t);
      }
      rangerPlugin = new RangerBasePlugin("cdap", "cdap");
    }
    rangerPlugin.init();
    RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
    rangerPlugin.setResultProcessor(auditHandler);
  }


  @Override
  public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
    LOG.info("===> enforce(EntityId entity, Principal principal, Action action)");
    LOG.info("Enforce called on entity {}, principal {}, action {}", entity, principal, action);
    if (rangerPlugin == null) {
      LOG.warn("CDAP Ranger Authorizer is not initialized");
      throw new RuntimeException("CDAP Ranger Authorizer is not initialized.");
    }

    String requestingUser = getRequestingUser();
    String ip = InetAddress.getLocalHost().getHostName();
    java.util.Set<String> userGroups = MiscUtil.getGroupsForRequestUser(requestingUser);
    LOG.info("Requesting user {}, ip {}, requesting user groups {}", requestingUser, ip, userGroups);

    Date eventTime = new Date();
    String accessType = toRangerAccessType(action);

    boolean validationFailed = false;

    RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl();
    rangerRequest.setUser(requestingUser);
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
      LOG.warn("Unsupported entity type {}" + entity.getEntityType());
      validationFailed = true;
    }

    boolean isAuthorized = true;
    if (validationFailed) {
      LOG.warn("Validation failed for request {}" + rangerRequest);
      isAuthorized = false;
    } else {
      try {
        RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
        if (result == null) {
          LOG.info("Ranger Plugin returned null. Returning false");
          isAuthorized = false;
        } else {
          isAuthorized = result.getIsAllowed();
        }
      } catch (Throwable t) {
        LOG.warn("Error while calling isAccessAllowed(). request {}", rangerRequest, t);
        throw t;
      } finally {
        LOG.debug("Ranger Request {}, Returning value {}", rangerRequest, isAuthorized);
      }
    }
    if (!isAuthorized) {
      LOG.info("Unauthorized: Principal {} is unauthorized to perform action {} on entity {}, " +
                 "accessType {}",
               principal, action, entity, accessType);
      throw new UnauthorizedException(principal, action, entity);
    }
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> set) throws Exception {
    LOG.info("===> enforce(EntityId entityId, Principal principal, Set<Action> set)");
    LOG.info("Enforce called on entity {}, principal {}, actions {}", entityId, principal, set);
    //TODO: Investigate if its possible to make the enforce call with set of actions rather than one by one
    for (Action action : set) {
      LOG.info("Calling enforce on action {}", action);
      enforce(entityId, principal, action);
      LOG.info("Enforce done on action {}", action);
    }
    LOG.info("<=== enforce(EntityId entityId, Principal principal, Set<Action> set)");
  }

  @Override
  public void grant(EntityId entity, Principal principal, java.util.Set<Action> actions) throws Exception {
    LOG.warn("Grant operation not supported by Ranger for CDAP");
  }

  @Override
  public void revoke(EntityId entity, Principal principal, java.util.Set<Action> actions) throws Exception {
    LOG.warn("Revoke operation not supported by Ranger for CDAP");
  }

  @Override
  public void revoke(EntityId entity) throws Exception {
    LOG.warn("Revoke for entity operation not supported by Ranger for CDAP");
  }

  @Override
  public void createRole(Role role) throws Exception {
    LOG.warn("Create role operation not supported by Ranger for CDAP");

  }

  @Override
  public void dropRole(Role role) throws Exception {
    LOG.warn("Drop role operation not supported by Ranger for CDAP");

  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
    LOG.warn("Add role to principal operation not supported by Ranger for CDAP");

  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
    LOG.warn("Remove role from principal operation not supported by Ranger for CDAP");

  }

  @Override
  public Set<Role> listRoles(Principal principal) throws Exception {
    LOG.warn("List roles operation not supported by Ranger for CDAP");
    return null;
  }

  @Override
  public Set<Role> listAllRoles() throws Exception {
    LOG.warn("List all roles operation not supported by Ranger for CDAP");
    return null;
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    LOG.warn("List privileges operation not supported by Ranger for CDAP");
    return null;
  }

  private String getRequestingUser() throws IllegalArgumentException {
    Principal principal = context.getPrincipal();
    return principal.getName();
  }

  private String toRangerAccessType(Action action) {
    return action.toString().toLowerCase();
  }
}
