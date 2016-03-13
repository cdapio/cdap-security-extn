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

/**
 * Represents the {@link Authorizable.AuthorizableType#STREAM} authorizable in CDAP
 */
public class Stream implements Authorizable {
  private final String name;

  /**
   * Create an {@link Authorizable.AuthorizableType#STREAM} authorizable of the given name.
   *
   * @param name Name of the {@link Authorizable.AuthorizableType#STREAM}
   */
  public Stream(String name) {
    this.name = name;
  }

  /**
   * Get type of {@link Authorizable.AuthorizableType#STREAM} authorizable.
   *
   * @return Type of {@link Authorizable.AuthorizableType#STREAM} authorizable.
   */
  @Override
  public AuthorizableType getAuthzType() {
    return AuthorizableType.STREAM;
  }

  /**
   * Get name of the {@link Authorizable.AuthorizableType#STREAM}.
   *
   * @return Name of the {@link Authorizable.AuthorizableType#STREAM}.
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * Get type name of {@link Authorizable.AuthorizableType#STREAM}.
   *
   * @return Type name of {@link Authorizable.AuthorizableType#STREAM} authorizable.
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
    Stream that = (Stream) o;
    return Objects.equals(name, that.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(name);
  }
}
