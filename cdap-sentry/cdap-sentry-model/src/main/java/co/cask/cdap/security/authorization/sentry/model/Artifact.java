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

import co.cask.cdap.api.artifact.ArtifactId;
import com.google.common.base.Preconditions;

import java.util.Objects;

/**
 * Represents the {@link Authorizable.AuthorizableType#ARTIFACT} authorizable in CDAP
 */
public class Artifact implements Authorizable {

  private static final String ARTIFACT_DETAILS_SEPARATOR = ".";

  private final String artifactName;
  private final String artifactVersion;

  /**
   * Create an {@link Authorizable.AuthorizableType#ARTIFACT} authorizable of the given name.
   *
   * @param artifactDetails Details of the {@link Authorizable.AuthorizableType#ARTIFACT} which must be in the
   * following format {@link ArtifactId#name artifactName}.{@link ArtifactId#version artifactVersion}
   */
  public Artifact(String artifactDetails) {
    String splitter = "\\" + ARTIFACT_DETAILS_SEPARATOR;
    String[] artifactNameVersion = artifactDetails.trim().split(splitter, 2);
    Preconditions.checkArgument(artifactNameVersion.length == 2, "Artifact details %s is invalid. Artifact details " +
      "must be in the following format: artifactName%sartifactVersion.", artifactDetails, ARTIFACT_DETAILS_SEPARATOR);
    this.artifactName = artifactNameVersion[0];
    this.artifactVersion = artifactNameVersion[1];
  }

  /**
   * Construct an {@link Authorizable.AuthorizableType#ARTIFACT} authorizable with a known artifact name and version
   *
   * @param artifactName the artifact name
   * @param artifactVersion the artifact version
   */
  public Artifact(String artifactName, String artifactVersion) {
    this.artifactName = artifactName;
    this.artifactVersion = artifactVersion;
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
   * Get the artifact details of the {@link Authorizable.AuthorizableType#ARTIFACT} in the following format
   * {@link ArtifactId#name artifactName}.{@link ArtifactId#version artifactVersion}
   *
   * @return Name of the {@link Authorizable.AuthorizableType#ARTIFACT}.
   */
  @Override
  public String getName() {
    return artifactName + ARTIFACT_DETAILS_SEPARATOR + artifactVersion;
  }

  /**
   * Gets name of the {@link Authorizable.AuthorizableType#ARTIFACT}.
   *
   * @return name of the {@link Authorizable.AuthorizableType#ARTIFACT}.
   */
  public String getArtifactName() {
    return artifactName;
  }

  /**
   * Gets version of the {@link Authorizable.AuthorizableType#ARTIFACT}.
   *
   * @return version of the {@link Authorizable.AuthorizableType#ARTIFACT}.
   */
  public String getArtifactVersion() {
    return artifactVersion;
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
    return Objects.equals(artifactName, that.artifactName) && Objects.equals(artifactVersion, that.artifactVersion);
  }

  @Override
  public int hashCode() {
    return Objects.hash(artifactName, artifactVersion);
  }
}
