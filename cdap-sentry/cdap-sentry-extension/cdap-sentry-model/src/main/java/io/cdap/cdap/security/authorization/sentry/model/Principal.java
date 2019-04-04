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

package io.cdap.cdap.security.authorization.sentry.model;

import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents the {@link Authorizable.AuthorizableType#PRINCIPAL} authorizable in CDAP
 */
public class Principal implements Authorizable {
  private final String name;

  public Principal(String name) {
    this.name = name;
  }

  @Override
  public AuthorizableType getAuthzType() {
    return AuthorizableType.PRINCIPAL;
  }

  @Nullable
  @Override
  public String getSubType() {
    // Principal does not have a sub-type
    return null;
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public String getTypeName() {
    return getAuthzType().name();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Principal principal = (Principal) o;
    return Objects.equals(name, principal.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name);
  }

  @Override
  public String toString() {
    return "Principal{" +
      "name='" + name + '\'' +
      "} " + super.toString();
  }
}
