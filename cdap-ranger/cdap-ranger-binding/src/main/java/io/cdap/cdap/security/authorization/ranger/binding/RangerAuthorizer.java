/*
 * Copyright © 2017-2019 Cask Data, Inc.
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
package io.cdap.cdap.security.authorization.ranger.binding;

import io.cdap.cdap.common.conf.Constants;
import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.proto.id.ApplicationId;
import io.cdap.cdap.proto.id.ArtifactId;
import io.cdap.cdap.proto.id.DatasetId;
import io.cdap.cdap.proto.id.DatasetModuleId;
import io.cdap.cdap.proto.id.DatasetTypeId;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.id.InstanceId;
import io.cdap.cdap.proto.id.KerberosPrincipalId;
import io.cdap.cdap.proto.id.NamespaceId;
import io.cdap.cdap.proto.id.ProgramId;
import io.cdap.cdap.proto.id.SecureKeyId;
import io.cdap.cdap.proto.id.StreamId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Authorizable;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.proto.security.Privilege;
import io.cdap.cdap.proto.security.Role;
import io.cdap.cdap.security.authorization.ranger.commons.RangerCommon;
import io.cdap.cdap.security.spi.authorization.AbstractAuthorizer;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;
import io.cdap.cdap.security.spi.authorization.Authorizer;
import io.cdap.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Preconditions;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.policyengine.RangerPolicyEngine;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * This class implements {@link Authorizer} from CDAP and is responsible for interacting with Ranger to enforce
 * authorization.
 */
public class RangerAuthorizer extends AbstractAuthorizer {
  private static final Logger LOG = LoggerFactory.getLogger(RangerAuthorizer.class);

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
      UserGroupInformation ugi = UserGroupInformation.getLoginUser();
      Preconditions.checkNotNull(ugi, "Kerberos login information is not available. UserGroupInformation is null");
      // set the login user as the user as whom cdap is running as this is needed for kerberos authentication
      MiscUtil.setUGILoginUser(ugi, null);
      LOG.debug("Initializing Ranger CDAP Plugin with UGI {}", ugi);

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
    // for enforcement we do authorization just on the entity in question unlike isVisible where we also
    // consider privileges on the children
    if (!enforce(entity, principal, RangerAccessRequest.ResourceMatchingScope.SELF, toRangerAccessType(action))) {
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
  public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {
    // for visibility we take bottom up approach i.e. an entity is visible if the the principal has any privilege on
    // the entity or any of descendants.
    Set<EntityId> visibleEntities = new HashSet<>(entityIds.size());
    for (EntityId entityId : entityIds) {
      if (enforce(entityId, principal, RangerAccessRequest.ResourceMatchingScope.SELF_OR_DESCENDANTS,
                  RangerPolicyEngine.ANY_ACCESS)) {
        visibleEntities.add(entityId);
      }
    }
    return visibleEntities;
  }

  @Override
  public void grant(Authorizable authorizable, Principal principal, Set<Action> set) throws Exception {
    throw new UnsupportedOperationException("Please use Ranger Admin UI to grant privileges.");
  }

  @Override
  public void revoke(Authorizable authorizable, Principal principal, Set<Action> set) throws Exception {
    throw new UnsupportedOperationException("Please use Ranger Admin UI to revoke privileges.");
  }

  @Override
  public void revoke(Authorizable authorizable) throws Exception {
    throw new UnsupportedOperationException("Please use Ranger Admin UI to revoke privileges.");
  }

  @Override
  public void createRole(Role role) throws Exception {
    throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
  }

  @Override
  public void dropRole(Role role) throws Exception {
    throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
    throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");

  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
    throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");

  }

  @Override
  public Set<Role> listRoles(Principal principal) throws Exception {
    throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
  }

  @Override
  public Set<Role> listAllRoles() throws Exception {
    throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    throw new UnsupportedOperationException("Please use Ranger Admin UI to list privileges.");
  }

  private boolean enforce(EntityId entity, Principal principal,
                          RangerAccessRequest.ResourceMatchingScope resourceMatchingScope, String accessType)
    throws Exception {
    LOG.debug("Enforce called on entity {}, principal {}, action {} and match scope {}", entity, principal,
              accessType, resourceMatchingScope);
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
    RangerAccessRequestImpl rangerRequest = new RangerAccessRequestImpl();
    rangerRequest.setUser(requestingUser);
    rangerRequest.setUserGroups(userGroups);
    rangerRequest.setClientIPAddress(ip);
    rangerRequest.setAccessTime(eventTime);
    rangerRequest.setResourceMatchingScope(resourceMatchingScope);

    RangerAccessResourceImpl rangerResource = new RangerAccessResourceImpl();
    rangerRequest.setResource(rangerResource);
    rangerRequest.setAccessType(accessType);

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
    return isAuthorized;
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
        rangerAccessResource.setValue(RangerCommon.KEY_INSTANCE, ((InstanceId) entityId).getInstance());
        break;
      case NAMESPACE:
        setAccessResource(new InstanceId(instanceName), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_NAMESPACE, ((NamespaceId) entityId).getNamespace());
        break;
      case ARTIFACT:
        ArtifactId artifactId = (ArtifactId) entityId;
        setAccessResource(artifactId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_ARTIFACT, artifactId.getArtifact());
        break;
      case APPLICATION:
        ApplicationId applicationId = (ApplicationId) entityId;
        setAccessResource(applicationId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_APPLICATION, applicationId.getApplication());
        break;
      case DATASET:
        DatasetId dataset = (DatasetId) entityId;
        setAccessResource(dataset.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_DATASET, dataset.getDataset());
        break;
      case DATASET_MODULE:
        DatasetModuleId datasetModuleId = (DatasetModuleId) entityId;
        setAccessResource(datasetModuleId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_DATASET_MODULE, datasetModuleId.getModule());
        break;
      case DATASET_TYPE:
        DatasetTypeId datasetTypeId = (DatasetTypeId) entityId;
        setAccessResource(datasetTypeId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_DATASET_TYPE, datasetTypeId.getType());
        break;
      case STREAM:
        StreamId streamId = (StreamId) entityId;
        setAccessResource(streamId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_STREAM, streamId.getStream());
        break;
      case PROGRAM:
        ProgramId programId = (ProgramId) entityId;
        setAccessResource(programId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_PROGRAM, programId.getType().getPrettyName().toLowerCase() +
          RangerCommon.RESOURCE_SEPARATOR + programId.getProgram());
        break;
      case SECUREKEY:
        SecureKeyId secureKeyId = (SecureKeyId) entityId;
        setAccessResource(secureKeyId.getParent(), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_SECUREKEY, secureKeyId.getName());
        break;
      case KERBEROSPRINCIPAL:
        setAccessResource(new InstanceId(instanceName), rangerAccessResource);
        rangerAccessResource.setValue(RangerCommon.KEY_PRINCIPAL, ((KerberosPrincipalId) entityId).getPrincipal());
        break;
      default:
        throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
    }
  }
}
