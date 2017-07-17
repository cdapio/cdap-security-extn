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
 * Represents the {@link Authorizable.AuthorizableType#DATASET} authorizable in CDAP
 */
public class Dataset implements Authorizable {
  private final String name;

  /**
   * Create an {@link Authorizable.AuthorizableType#DATASET} authorizable of the given name.
   *
   * @param name Name of the {@link Authorizable.AuthorizableType#DATASET}
   */
  public Dataset(String name) {
    this.name = name;
  }

  /**
   * Get type of {@link Authorizable.AuthorizableType#DATASET} authorizable.
   *
   * @return Type of {@link Authorizable.AuthorizableType#DATASET} authorizable.
   */
  @Override
  public AuthorizableType getAuthzType() {
    return AuthorizableType.DATASET;
  }

  /**
   * Get name of the {@link Authorizable.AuthorizableType#DATASET}.
   *
   * @return Name of the {@link Authorizable.AuthorizableType#DATASET}.
   */
  @Override
  public String getName() {
    return name;
  }

  @Nullable
  @Override
  public String getSubType() {
    // Dataset does not have a sub type
    return null;
  }

  /**
   * Get type name of {@link Authorizable.AuthorizableType#DATASET}.
   *
   * @return Type name of {@link Authorizable.AuthorizableType#DATASET} authorizable.
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
    Dataset that = (Dataset) o;
    return Objects.equals(name, that.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name);
  }
}
