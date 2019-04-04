/*
 * Copyright 2016-2019 Cask Data, Inc.
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
 * Represents the {@link Authorizable.AuthorizableType#ARTIFACT} authorizable in CDAP
 */
public class Artifact implements Authorizable {

  private final String artifactName;

  /**
   * Construct an {@link Authorizable.AuthorizableType#ARTIFACT} authorizable with a known artifact name and version
   *
   * @param artifactName the artifact name
   */
  public Artifact(String artifactName) {
    this.artifactName = artifactName;
  }

  /**
   * Get type of {@link Authorizable.AuthorizableType#ARTIFACT} authorizable.
   *
   * @return Type of {@link Authorizable.AuthorizableType#ARTIFACT} authorizable.
   */
  @Override
  public AuthorizableType getAuthzType() {
    return AuthorizableType.ARTIFACT;
  }

  /**
   * @return Name of the {@link Authorizable.AuthorizableType#ARTIFACT}.
   */
  @Override
  public String getName() {
    return artifactName;
  }

  @Nullable
  @Override
  public String getSubType() {
    // Artifact does not have a sub type
    return null;
  }

  /**
   * Get type name of {@link Authorizable.AuthorizableType#ARTIFACT}.
   *
   * @return Type name of {@link Authorizable.AuthorizableType#ARTIFACT} authorizable.
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
    Artifact that = (Artifact) o;
    return Objects.equals(artifactName, that.artifactName);
  }

  @Override
  public int hashCode() {
    return Objects.hash(artifactName);
  }
}
