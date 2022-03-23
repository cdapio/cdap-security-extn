/*
 * Copyright © 2021-2022 Cask Data, Inc.
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

package io.cdap.cdap.security.authorization.ldap.role.permission;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Enum with Permissions for roles
 */
public enum RolePermission {
  // Namespace
  @JsonProperty("Create Namespace")
  CREATE_NAMESPACE,
  @JsonProperty("View Namespace")
  VIEW_NAMESPACE,
  @JsonProperty("Modify Namespace")
  MODIFY_NAMESPACE,
  @JsonProperty("Delete Namespace")
  DELETE_NAMESPACE,

  // Pipeline
  @JsonProperty("Create Pipeline")
  CREATE_PIPELINE,
  @JsonProperty("Deploy Pipeline")
  DEPLOY_PIPELINE,
  @JsonProperty("Execute Pipeline")
  EXECUTE_PIPELINE,
  @JsonProperty("View Pipeline")
  VIEW_PIPELINE,
  @JsonProperty("Preview Pipeline")
  PREVIEW_PIPELINE,
  @JsonProperty("Delete Pipeline")
  DELETE_PIPELINE,
  @JsonProperty("Modify Pipeline")
  MODIFY_PIPELINE,

  // Schedule
  @JsonProperty("Create Schedule")
  CREATE_SCHEDULE,
  @JsonProperty("Change Schedule")
  CHANGE_SCHEDULE,

  // Schedule
  @JsonProperty("Create Triggers")
  CREATE_TRIGGERS,
  @JsonProperty("Set Triggers")
  SET_TRIGGERS,

  // Schedule
  @JsonProperty("Create Tag")
  CREATE_TAG,
  @JsonProperty("View Tags")
  VIEW_TAGS,
  @JsonProperty("Delete Tag")
  DELETE_TAG,

  @JsonProperty("View Logs")
  VIEW_LOGS,
  @JsonProperty("View Metadata")
  VIEW_METADATA,

  // Artifacts
  @JsonProperty("Deploy Artifacts")
  DEPLOY_ARTIFACTS,
  @JsonProperty("Deploy Drivers")
  DEPLOY_DRIVERS,

  // Studio
  @JsonProperty("Use Studio")
  USE_STUDIO,

  // Wrangle
  @JsonProperty("Use Wrangler")
  USE_WRANGLER,

  // Compute Profile
  @JsonProperty("Create Compute Profile")
  CREATE_COMPUTE_PROFILE,
  @JsonProperty("View Compute Profile")
  VIEW_COMPUTE_PROFILE,
  @JsonProperty("Modify Compute Profile")
  MODIFY_COMPUTE_PROFILE,
  @JsonProperty("Delete Compute Profile")
  DELETE_COMPUTE_PROFILE,

  // Secret Key
  @JsonProperty("Manage Secure Key")
  MANAGE_SECURE_KEY,
  @JsonProperty("View Secure Key")
  VIEW_SECURE_KEY,

  // System Preferences
  @JsonProperty("Manage System Preferences")
  MANAGE_SYSTEM_PREFERENCES,
  @JsonProperty("View System Services")
  VIEW_SYSTEM_SERVICES,

  // System Administration
  @JsonProperty("Initiate And Accept Tether")
  INITIATE_AND_ACCEPT_TETHER,
  @JsonProperty("Perform Health Check")
  PERFORM_HEALTH_CHECK,
}
