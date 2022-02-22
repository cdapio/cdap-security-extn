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

package io.cdap.cdap.security.authorization.ldap.role.group;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import io.cdap.cdap.security.authorization.ldap.role.permission.RolePermission;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Config of mapping {@link Role} to {@link RolePermission} and LDAP groups
 */
public class RoleWithGroupsMappingConfig {
  private Map<String, Role> roles;

  @JsonProperty("mappings")
  private Map<String, GroupWithRoles> roleMapping;

  private Set<String> fullAccessUsers;

  public RoleWithGroupsMappingConfig() {
    roles = new HashMap<>();
    roleMapping = new HashMap<>();
    fullAccessUsers = Collections.emptySet();
  }

  public RoleWithGroupsMappingConfig(Map<String, Role> roles, Map<String, GroupWithRoles> roleMapping,
                                     Set<String> fullAccessUsers) {
    this.roles = roles;
    this.roleMapping = roleMapping;
    this.fullAccessUsers = fullAccessUsers;
  }

  public Map<String, Role> getRoles() {
    return roles;
  }

  public Map<String, GroupWithRoles> getRoleMapping() {
    return roleMapping;
  }

  public Set<String> getFullAccessUsers() {
    return fullAccessUsers;
  }

  public void setRoles(Map<String, Role> roles) {
    this.roles = roles;
  }

  @JsonSetter
  public void setRoles(List<Role> roles) {
    this.roles = roles.stream()
      .collect(Collectors.toMap(Role::getName, Function.identity()));
  }

  public void setRoleMapping(Map<String, GroupWithRoles> roleMapping) {
    this.roleMapping = roleMapping;
  }

  @JsonSetter
  public void setRoleMapping(List<GroupWithRoles> roleMapping) {
    this.roleMapping = roleMapping.stream()
      .collect(Collectors.toMap(GroupWithRoles::getGroup, Function.identity()));
  }

  public void setFullAccessUsers(Set<String> fullAccessUsers) {
    this.fullAccessUsers = new HashSet<>(fullAccessUsers);
  }

  public boolean isEmpty() {
    return roles.isEmpty() && roleMapping.isEmpty();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RoleWithGroupsMappingConfig that = (RoleWithGroupsMappingConfig) o;
    return Objects.equals(roles, that.roles) && Objects.equals(roleMapping, that.roleMapping);
  }

  @Override
  public int hashCode() {
    return Objects.hash(roles, roleMapping);
  }
}
