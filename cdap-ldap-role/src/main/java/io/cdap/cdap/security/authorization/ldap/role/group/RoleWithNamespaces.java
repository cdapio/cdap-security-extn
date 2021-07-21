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
 * Role with list of namespaces
 */
public class RoleWithNamespaces {
  private String role;
  private List<String> namespaces;

  public RoleWithNamespaces() {
    namespaces = Collections.emptyList();
  }

  public String getRole() {
    return role;
  }

  public List<String> getNamespaces() {
    return new ArrayList<>(namespaces);
  }

  public void setRole(String role) {
    this.role = role;
  }

  public void setNamespaces(List<String> namespaces) {
    if (namespaces == null) {
      this.namespaces = Collections.emptyList();
    } else {
      this.namespaces = new ArrayList<>(namespaces);
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
    RoleWithNamespaces that = (RoleWithNamespaces) o;
    return Objects.equals(role, that.role) && Objects.equals(namespaces, that.namespaces);
  }

  @Override
  public int hashCode() {
    return Objects.hash(role, namespaces);
  }
}
