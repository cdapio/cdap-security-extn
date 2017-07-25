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

import co.cask.cdap.common.conf.Constants;
import co.cask.cdap.proto.element.EntityType;
import co.cask.cdap.proto.id.ApplicationId;
import co.cask.cdap.proto.id.ArtifactId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.DatasetModuleId;
import co.cask.cdap.proto.id.DatasetTypeId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.InstanceId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.SecureKeyId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import co.cask.cdap.proto.security.Role;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.Authorizer;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Preconditions;
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
import java.util.Properties;
import java.util.Set;

/**
 * This class implements {@link Authorizer} from CDAP and is responsible for interacting with Ranger to enforce
 * authorization.
 */
public class RangerAuthorizer extends AbstractAuthorizer {
  private static final Logger LOG = LoggerFactory.getLogger(RangerAuthorizer.class);

  // just string keys used to store entity in ranger. We don't want them to be derived from entity type or name since
  // any changes to them on cdap side will make privileges incompatible.
  private static final String KEY_INSTANCE = "instance";
  private static final String KEY_NAMESPACE = "namespace";
  private static final String KEY_ARTIFACT = "artifact";
  private static final String KEY_APPLICATION = "application";
  private static final String KEY_DATASET = "dataset";
  private static final String KEY_STREAM = "stream";
  private static final String KEY_PROGRAM = "program";
  private static final String KEY_DATASET_MODULE = "dataset_module";
  private static final String KEY_DATASET_TYPE = "dataset_type";
  private static final String KEY_SECUREKEY = "securekey";

  // using # as we don't allow it in entity names
  private static final String RESOURCE_SEPARATOR = "#";

  private static volatile RangerBasePlugin rangerPlugin = null;
  private AuthorizationContext context;
  // cdap instance name
  private String instanceName;

  @Override
  public synchronized void initialize(AuthorizationContext context) throws Exception {
    this.context = context;
    Properties properties = context.getExtensionProperties();
    instanceName = properties.containsKey(Constants.INSTANCE_NAME) ?
      properties.getProperty(Constants.INSTANCE_NAME) : "cdap";
    if (rangerPlugin == null) {
      try {
        UserGroupInformation ugi = UserGroupInformation.getLoginUser();
        Preconditions.checkNotNull(ugi, "Kerberos login information is not available. UserGroupInformation is null");
        // set the login user as the user as whom cdap is running as this is needed for kerberos authentication
        MiscUtil.setUGILoginUser(ugi, null);
        LOG.debug("Initializing Ranger CDAP Plugin with UGI {}", ugi);
      } catch (Throwable t) {
        LOG.error("Error getting principal.", t);
      }
      // the string name here should not be changed as this uniquely identifies the plugin in ranger. If it's
      // changed it will require changing all the supporting xml file which is in this package.
      rangerPlugin = new RangerBasePlugin("cdap", "cdap");
    }
    rangerPlugin.init();
    RangerDefaultAuditHandler auditHandler = new RangerDefaultAuditHandler();
    rangerPlugin.setResultProcessor(auditHandler);
  }

  @Override
  public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
    LOG.debug("Enforce called on entity {}, principal {}, action {}", entity, principal, action);
    if (rangerPlugin == null) {
      throw new RuntimeException("CDAP Ranger Authorizer is not initialized.");
    }

    if (principal.getType() != Principal.PrincipalType.USER) {
      throw new IllegalArgumentException(String.format("The principal type for current enforcement request is '%s'. " +
                                                         "Authorization enforcement is only supported for '%s'.",
                                                       principal.getType(), Principal.PrincipalType.USER));
    }
    String requestingUser = principal.getName();
    String ip = InetAddress.getLocalHost().getHostName();
    Set<String> userGroups = MiscUtil.getGroupsForRequestUser(requestingUser);

    LOG.debug("Requesting user {}, ip {}, requesting user groups {}", requestingUser, ip, userGroups);

    Date eventTime = new Date();
    String accessType = toRangerAccessType(action);
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

    setAccessResource(entity, rangerResource);

    boolean isAuthorized = false;

    try {
      RangerAccessResult result = rangerPlugin.isAccessAllowed(rangerRequest);
      if (result == null) {
        LOG.warn("Unauthorized: Ranger Plugin returned null for this authorization enforcement.");
        isAuthorized = false;
      } else {
        isAuthorized = result.getIsAllowed();
      }
    } catch (Throwable t) {
      LOG.warn("Error while calling isAccessAllowed(). request {}", rangerRequest, t);
      throw t;
    } finally {
      LOG.trace("Ranger Request {}, authorization {}.", rangerRequest, (isAuthorized ? "successful" : "failed"));
    }

    if (!isAuthorized) {
      throw new UnauthorizedException(principal, action, entity);
    }
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> set) throws Exception {
    LOG.debug("Enforce called on entity {}, principal {}, actions {}", entityId, principal, set);
    //TODO: Investigate if its possible to make the enforce call with set of actions rather than one by one
    for (Action action : set) {
      enforce(entityId, principal, action);
    }
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

  /**
   * Sets the access resource appropriately depending on the given entityId
   *
   * @param entityId the entity which needs to be set to
   * @param rangerAccessResource the {@link RangerAccessResourceImpl} to set the entity values to
   */
  private void setAccessResource(EntityId entityId, RangerAccessResourceImpl rangerAccessResource) {
    EntityType entityType = entityId.getEntityType();
    switch (entityType) {
      case INSTANCE:
        rangerAccessResource.setValue(KEY_INSTANCE, ((InstanceId) entityId).getInstance());
        break;
      case NAMESPACE:
        setAccessResource(new InstanceId(instanceName), rangerAccessResource);
        rangerAccessResource.setValue(KEY_NAMESPACE, ((NamespaceId) entityId).getNamespace());
        break;
      case ARTIFACT:
        ArtifactId artifactId = (ArtifactId) entityId;
        setAccessResource(artifactId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(KEY_ARTIFACT, artifactId.getArtifact() + RESOURCE_SEPARATOR +
          artifactId.getVersion());
        break;
      case APPLICATION:
        ApplicationId applicationId = (ApplicationId) entityId;
        setAccessResource(applicationId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(KEY_APPLICATION, applicationId.getApplication() + RESOURCE_SEPARATOR +
          applicationId.getVersion());
        break;
      case DATASET:
        DatasetId dataset = (DatasetId) entityId;
        setAccessResource(dataset.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(KEY_DATASET, dataset.getDataset());
        break;
      case DATASET_MODULE:
        DatasetModuleId datasetModuleId = (DatasetModuleId) entityId;
        setAccessResource(datasetModuleId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(KEY_DATASET_MODULE, datasetModuleId.getModule());
        break;
      case DATASET_TYPE:
        DatasetTypeId datasetTypeId = (DatasetTypeId) entityId;
        setAccessResource(datasetTypeId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(KEY_DATASET_TYPE, datasetTypeId.getType());
        break;
      case STREAM:
        StreamId streamId = (StreamId) entityId;
        setAccessResource(streamId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(KEY_STREAM, streamId.getStream());
        break;
      case PROGRAM:
        ProgramId programId = (ProgramId) entityId;
        setAccessResource(programId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(KEY_PROGRAM, programId.getType() + RESOURCE_SEPARATOR + programId.getProgram());
        break;
      case SECUREKEY:
        SecureKeyId secureKeyId = (SecureKeyId) entityId;
        setAccessResource(secureKeyId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(KEY_SECUREKEY, secureKeyId.getName());
        break;
      default:
        throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
    }
  }
}
