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

import io.cdap.cdap.security.authorization.ldap.role.permission.RolePermission;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Role with list of {@link RolePermission}
 */
public class Role {
  private String name;
  private List<RolePermission> permissions;

  public Role() {
    permissions = Collections.emptyList();
  }

  public Role(String name, List<RolePermission> permissions) {
    this.name = name;
    this.permissions = new ArrayList<>(permissions);
  }

  public String getName() {
    return name;
  }

  public List<RolePermission> getPermissions() {
    return new ArrayList<>(permissions);
  }

  public void setName(String name) {
    this.name = name;
  }

  public void setPermissions(List<RolePermission> permissions) {
    if (permissions == null) {
      this.permissions = Collections.emptyList();
    } else {
      this.permissions = new ArrayList<>(permissions);
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Role role = (Role) o;
    return Objects.equals(name, role.name) && Objects.equals(permissions, role.permissions);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, permissions);
  }
}
