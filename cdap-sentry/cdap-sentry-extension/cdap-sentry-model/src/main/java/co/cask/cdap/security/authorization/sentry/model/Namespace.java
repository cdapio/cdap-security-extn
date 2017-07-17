/*
 * Copyright 2016 Cask Data, Inc.
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

package co.cask.cdap.security.authorization.sentry.model;

import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents the {@link Authorizable.AuthorizableType#NAMESPACE} authorizable in CDAP
 */
public class Namespace implements Authorizable {
  private final String name;

  /**
   * Create an {@link Authorizable.AuthorizableType#NAMESPACE} authorizable of the given name.
   *
   * @param name Name of the {@link Authorizable.AuthorizableType#NAMESPACE}
   */
  public Namespace(String name) {
    this.name = name;
  }

  /**
   * Get type of {@link Authorizable.AuthorizableType#NAMESPACE} authorizable.
   *
   * @return Type of {@link Authorizable.AuthorizableType#NAMESPACE} authorizable.
   */
  @Override
  public AuthorizableType getAuthzType() {
    return AuthorizableType.NAMESPACE;
  }

  /**
   * Get name of the {@link Authorizable.AuthorizableType#NAMESPACE}.
   *
   * @return Name of the {@link Authorizable.AuthorizableType#NAMESPACE}.
   */
  @Override
  public String getName() {
    return name;
  }

  @Nullable
  @Override
  public String getSubType() {
    // Namespace does not have a sub type
    return null;
  }

  /**
   * Get type name of {@link Authorizable.AuthorizableType#NAMESPACE}.
   *
   * @return Type name of {@link Authorizable.AuthorizableType#NAMESPACE} authorizable.
   */
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
    Namespace that = (Namespace) o;
    return Objects.equals(name, that.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name);
  }
}
