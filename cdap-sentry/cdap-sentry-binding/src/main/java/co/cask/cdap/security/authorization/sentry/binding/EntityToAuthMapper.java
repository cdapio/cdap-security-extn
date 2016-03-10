/*
 * Copyright © 2016 Cask Data, Inc.
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

package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.proto.element.EntityType;
import co.cask.cdap.proto.id.ApplicationId;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.id.NamespacedArtifactId;
import co.cask.cdap.proto.id.ProgramId;
import co.cask.cdap.proto.id.StreamId;
import co.cask.cdap.security.authorization.sentry.model.Application;
import co.cask.cdap.security.authorization.sentry.model.Artifact;
import co.cask.cdap.security.authorization.sentry.model.Authorizable;
import co.cask.cdap.security.authorization.sentry.model.Dataset;
import co.cask.cdap.security.authorization.sentry.model.Instance;
import co.cask.cdap.security.authorization.sentry.model.Namespace;
import co.cask.cdap.security.authorization.sentry.model.Program;
import co.cask.cdap.security.authorization.sentry.model.Stream;

import java.util.LinkedList;
import java.util.List;

/**
 * Converts {@link EntityId} to a {@link List} of {@link Authorizable}
 */
class EntityToAuthMapper {
  public static List<org.apache.sentry.core.common.Authorizable> convertEntityToAuthorizable(
    final String instanceName, final EntityId entityId) {
    List<org.apache.sentry.core.common.Authorizable> authorizables = new LinkedList<>();
    // cdap instance is not a concept in cdap entities. In sentry integration we need to grant privileges on the
    // instance so that users can create namespace inside the instance etc.
    authorizables.add(new Instance(instanceName));
    getAuthorizable(entityId, authorizables);
    return authorizables;
  }

  /**
   * Maps {@link EntityId} to a {@link List} of {@link Authorizable} by recursively working its way from a given
   * entity.
   *
   * @param entityId {@link EntityId} the entity which needs to be mapped to a list of authorizables
   * @param authorizables {@link List} of {@link Authorizable} to add authorizables to
   */
  private static void getAuthorizable(EntityId entityId, List<org.apache.sentry.core.common.Authorizable>
    authorizables) {
    EntityType entityType = entityId.getEntity();
    switch (entityType) {
      case NAMESPACE:
        authorizables.add(new Namespace(((NamespaceId) entityId).getNamespace()));
        break;
      case ARTIFACT:
        NamespacedArtifactId artifactId = (NamespacedArtifactId) entityId;
        getAuthorizable(artifactId.getParent(), authorizables);
        authorizables.add(new Artifact((artifactId).getArtifact()));
        break;
      case APPLICATION:
        ApplicationId applicationId = (ApplicationId) entityId;
        getAuthorizable(applicationId.getParent(), authorizables);
        authorizables.add(new Application((applicationId).getApplication()));
        break;
      case DATASET:
        DatasetId dataset = (DatasetId) entityId;
        getAuthorizable(dataset.getParent(), authorizables);
        authorizables.add(new Dataset((dataset).getDataset()));
        break;
      case STREAM:
        StreamId streamId = (StreamId) entityId;
        getAuthorizable(streamId.getParent(), authorizables);
        authorizables.add(new Stream((streamId).getStream()));
        break;
      case PROGRAM:
        ProgramId programId = (ProgramId) entityId;
        getAuthorizable(programId.getParent(), authorizables);
        authorizables.add(new Program(programId.getProgram()));
        break;
      default:
        throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
    }
  }
}
