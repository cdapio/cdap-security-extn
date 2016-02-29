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
 * Represents authorizable resources.
 * <p/>
 * Dataset access from program:
 * --------------------------------------------------------------------------------------------------------------------
 * | INSTANCE    | CDAP Instance, users needs access to this resource to perform operation on the instance like       |
 * |             | creating a namespace, listing namespaces etc.                                                      |
 * --------------------------------------------------------------------------------------------------------------------
 * | NAMESPACE   |
 * | ARTIFACT    |
 * | APPLICATION |
 * | PROGRAM     |
 * | DATASET     |
 * | STREAM      |
 * --------------------------------------------------------------------------------------------------------------------
 */
public interface Authorizable extends org.apache.sentry.core.common.Authorizable {
  String ALL = "*";

  /**
   * Enum of different {@link Authorizable}
   */
  public enum AuthorizableType {
    INSTANCE,
    NAMESPACE,
    ARTIFACT,
    APPLICATION,
    PROGRAM,
    DATASET,
    STREAM
  }

  ;

  AuthorizableType getAuthzType();
}
