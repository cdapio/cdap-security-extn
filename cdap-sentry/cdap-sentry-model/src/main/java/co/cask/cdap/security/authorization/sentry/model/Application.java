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

/**
 * Represents the {@link Authorizable.AuthorizableType#APPLICATION} authorizable in CDAP
 */
public class Application implements Authorizable {
  private final String name;

  /**
   * Create an {@link Authorizable.AuthorizableType#APPLICATION} authorizable of the given name.
   *
   * @param name Name of the {@link Authorizable.AuthorizableType#APPLICATION}
   */
  public Application(String name) {
    this.name = name;
  }

  /**
   * Get type of {@link Authorizable.AuthorizableType#APPLICATION} authorizable.
   *
   * @return Type of {@link Authorizable.AuthorizableType#APPLICATION} authorizable.
   */
  @Override
  public AuthorizableType getAuthzType() {
    return AuthorizableType.APPLICATION;
  }

  /**
   * Get name of the {@link Authorizable.AuthorizableType#APPLICATION}.
   *
   * @return Name of the {@link Authorizable.AuthorizableType#APPLICATION}.
   */
  @Override
  public String getName() {
    return name;
  }

  /**
   * Get type name of {@link Authorizable.AuthorizableType#APPLICATION}.
   *
   * @return Type name of {@link Authorizable.AuthorizableType#APPLICATION} authorizable.
   */
  @Override
  public String getTypeName() {
    return getAuthzType().name();
  }
}
