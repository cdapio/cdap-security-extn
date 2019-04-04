/*
 * Copyright © 2016-2019 Cask Data, Inc.
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

package io.cdap.cdap.security.authorization.sentry.policy;

import io.cdap.cdap.security.authorization.sentry.model.Application;
import io.cdap.cdap.security.authorization.sentry.model.Artifact;
import io.cdap.cdap.security.authorization.sentry.model.Authorizable;
import io.cdap.cdap.security.authorization.sentry.model.Authorizable.AuthorizableType;
import io.cdap.cdap.security.authorization.sentry.model.Dataset;
import io.cdap.cdap.security.authorization.sentry.model.DatasetModule;
import io.cdap.cdap.security.authorization.sentry.model.DatasetType;
import io.cdap.cdap.security.authorization.sentry.model.Instance;
import io.cdap.cdap.security.authorization.sentry.model.Namespace;
import io.cdap.cdap.security.authorization.sentry.model.Principal;
import io.cdap.cdap.security.authorization.sentry.model.Program;
import io.cdap.cdap.security.authorization.sentry.model.SecureKey;
import io.cdap.cdap.security.authorization.sentry.model.Stream;
import org.apache.sentry.policy.common.KeyValue;

import java.util.NoSuchElementException;

/**
 * Class to create {@link Authorizable} from {@link AuthorizableType} and name
 */
public final class ModelAuthorizables {

  private ModelAuthorizables() {
  }

  /**
   * Gets a {@link Authorizable} from the given key and value
   *
   * @param key the {@link AuthorizableType type} of the authorizable
   * @param value the {@link Authorizable name} of the authorizable
   * @return the created {@link Authorizable} with the given name if {@link AuthorizableType} given was valid
   * @throws NoSuchElementException if the given {@link AuthorizableType} was not valid
   */
  public static Authorizable from(String key, String value) {
    return from(new KeyValue(key, value));
  }

  /**
   * Gets a {@link Authorizable} from the given {@link KeyValue}
   *
   * @param keyValue {@link KeyValue} containing the {@link AuthorizableType} and name of the {@link Authorizable}
   * to be crearted
   * @return the created {@link Authorizable} with the given name if {@link AuthorizableType} given was valid
   * @throws NoSuchElementException if the given {@link AuthorizableType} was not valid
   */
  static Authorizable from(String keyValue) {
    return from(new KeyValue(keyValue));
  }

  private static Authorizable from(KeyValue keyValue) {
    String prefix = keyValue.getKey().toLowerCase();
    String name = keyValue.getValue();
    for (Authorizable.AuthorizableType type : AuthorizableType.values()) {
      if (prefix.equalsIgnoreCase(type.name())) {
        return from(type, name);
      }
    }
    throw new NoSuchElementException(String.format("Given AuthorizableType %s does not exists.", prefix));
  }

  private static Authorizable from(AuthorizableType type, String name) {
    switch (type) {
      case INSTANCE:
        return new Instance(name);
      case NAMESPACE:
        return new Namespace(name);
      case ARTIFACT:
        return new Artifact(name);
      case APPLICATION:
        return new Application(name);
      case PROGRAM:
        return new Program(name);
      case STREAM:
        return new Stream(name);
      case DATASET:
        return new Dataset(name);
      case DATASET_MODULE:
        return new DatasetModule(name);
      case DATASET_TYPE:
        return new DatasetType(name);
      case SECUREKEY:
        return new SecureKey(name);
      case PRINCIPAL:
        return new Principal(name);
      default:
        throw new NoSuchElementException(String.format("Given AuthorizableType %s does not exist.", type));
    }
  }
}
