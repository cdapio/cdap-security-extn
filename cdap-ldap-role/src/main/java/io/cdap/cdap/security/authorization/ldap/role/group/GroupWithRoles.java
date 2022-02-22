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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Group with list of {@link RoleWithNamespaces}
 */
public class GroupWithRoles {
  private String group;

  private List<RoleWithNamespaces> roles;

  public GroupWithRoles() {
    roles = Collections.emptyList();
  }

  public String getGroup() {
    return group;
  }

  public List<RoleWithNamespaces> getRoles() {
    return new ArrayList<>(roles);
  }

  public void setGroup(String group) {
    this.group = group;
  }

  public void setRoles(List<RoleWithNamespaces> roles) {
    if (roles == null) {
      this.roles = Collections.emptyList();
    } else {
      this.roles = new ArrayList<>(roles);
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
    GroupWithRoles that = (GroupWithRoles) o;
    return Objects.equals(group, that.group) && Objects.equals(roles, that.roles);
  }

  @Override
  public int hashCode() {
    return Objects.hash(group, roles);
  }
}
