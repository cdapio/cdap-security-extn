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

import org.junit.Assert;
import org.junit.Test;

/**
 * Test for different {@link Authorizable}
 */
public class TestAuthorizable {

  @Test
  public void testAuth() {

    String name = "test";

    Instance instance = new Instance(name);
    Assert.assertEquals(name, instance.getName());
    Assert.assertEquals(Authorizable.AuthorizableType.INSTANCE, instance.getAuthzType());

    Namespace namespace = new Namespace(name);
    Assert.assertEquals(name, namespace.getName());
    Assert.assertEquals(Authorizable.AuthorizableType.NAMESPACE, namespace.getAuthzType());

    Artifact artifact = new Artifact("art");
    Assert.assertEquals("art", artifact.getName());
    Assert.assertEquals(Authorizable.AuthorizableType.ARTIFACT, artifact.getAuthzType());

    Application application = new Application(name);
    Assert.assertEquals(name, application.getName());
    Assert.assertEquals(Authorizable.AuthorizableType.APPLICATION, application.getAuthzType());

    Dataset dataset = new Dataset(name);
    Assert.assertEquals(name, dataset.getName());
    Assert.assertEquals(Authorizable.AuthorizableType.DATASET, dataset.getAuthzType());

    Principal principal = new Principal(name);
    Assert.assertEquals(name, principal.getName());
    Assert.assertEquals(Authorizable.AuthorizableType.PRINCIPAL, principal.getAuthzType());
  }
}
