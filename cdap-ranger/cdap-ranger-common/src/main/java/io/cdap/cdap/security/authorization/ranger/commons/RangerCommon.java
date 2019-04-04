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
package io.cdap.cdap.security.authorization.ranger.commons;

/**
 * Commons shared between ranger-binding and ranger-lookup
 */
public class RangerCommon {

  // just string keys used to store entity in ranger. We don't want them to be derived from entity type or name since
  // any changes to them on cdap side will make privileges incompatible.
  public static final String KEY_INSTANCE = "instance";
  public static final String KEY_NAMESPACE = "namespace";
  public static final String KEY_ARTIFACT = "artifact";
  public static final String KEY_APPLICATION = "application";
  public static final String KEY_DATASET = "dataset";
  public static final String KEY_STREAM = "stream";
  public static final String KEY_PROGRAM = "program";
  public static final String KEY_DATASET_MODULE = "dataset_module";
  public static final String KEY_DATASET_TYPE = "dataset_type";
  public static final String KEY_SECUREKEY = "securekey";
  public static final String KEY_PRINCIPAL = "principal";

  public static final String RESOURCE_SEPARATOR = ".";

}
