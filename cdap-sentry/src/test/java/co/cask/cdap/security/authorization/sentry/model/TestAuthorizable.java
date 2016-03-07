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

import org.junit.Assert;
import org.junit.Test;

/**
 * Test for different {@link Authorizable}
 */
public class TestAuthorizable {

  @Test
  public void testAuth() throws Exception {

    String name = "test";

    Instance instance = new Instance(name);
    Assert.assertEquals(instance.getName(), name);
    Assert.assertEquals(instance.getAuthzType(), Authorizable.AuthorizableType.INSTANCE);

    Namespace namespace = new Namespace(name);
    Assert.assertEquals(namespace.getName(), name);
    Assert.assertEquals(namespace.getAuthzType(), Authorizable.AuthorizableType.NAMESPACE);

    Artifact artifact = new Artifact(name);
    Assert.assertEquals(artifact.getName(), name);
    Assert.assertEquals(artifact.getAuthzType(), Authorizable.AuthorizableType.ARTIFACT);

    Application application = new Application(name);
    Assert.assertEquals(application.getName(), name);
    Assert.assertEquals(application.getAuthzType(), Authorizable.AuthorizableType.APPLICATION);

    Program program = new Program(name);
    Assert.assertEquals(program.getName(), name);
    Assert.assertEquals(program.getAuthzType(), Authorizable.AuthorizableType.PROGRAM);

    Stream stream = new Stream(name);
    Assert.assertEquals(stream.getName(), name);
    Assert.assertEquals(stream.getAuthzType(), Authorizable.AuthorizableType.STREAM);

    Dataset dataset = new Dataset(name);
    Assert.assertEquals(dataset.getName(), name);
    Assert.assertEquals(dataset.getAuthzType(), Authorizable.AuthorizableType.DATASET);
  }
}
