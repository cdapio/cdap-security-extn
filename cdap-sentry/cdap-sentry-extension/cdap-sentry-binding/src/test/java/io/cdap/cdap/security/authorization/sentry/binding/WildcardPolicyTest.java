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

package io.cdap.cdap.security.authorization.sentry.binding;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import io.cdap.cdap.security.authorization.sentry.model.ActionFactory;
import io.cdap.cdap.security.authorization.sentry.model.Application;
import io.cdap.cdap.security.authorization.sentry.model.Authorizable;
import io.cdap.cdap.security.authorization.sentry.model.Dataset;
import io.cdap.cdap.security.authorization.sentry.model.Namespace;
import io.cdap.cdap.security.authorization.sentry.model.Program;
import io.cdap.cdap.security.authorization.sentry.policy.ModelAuthorizables;
import org.junit.Assert;
import org.junit.Test;

/**
 * Tests {@link WildcardPolicy} with various cases.
 */
public class WildcardPolicyTest {
  @Test
  public void testSimplePolicy() {
    WildcardPolicy readPolicy = createPolicy("read", toAuth("dataset", "table"));

    Assert.assertTrue(readPolicy.isAllowed(ImmutableList.of(new Dataset("table")), new ActionFactory.Action("read")));
    Assert.assertTrue(readPolicy.isAllowed(ImmutableList.of(new Dataset("table")), new ActionFactory.Action("READ")));

    Assert.assertFalse(readPolicy.isAllowed(ImmutableList.of(new Dataset("table")), new ActionFactory.Action("WRITE")));
    Assert.assertFalse(readPolicy.isAllowed(ImmutableList.of(new Dataset("Table")), new ActionFactory.Action("read")));
  }

  @Test
  public void testProgramPolicy() {
    WildcardPolicy readPolicy = createPolicy("execute",
                                             toAuth("namespace", "ns1"),
                                             toAuth("application", "app1"),
                                             toAuth("program", "Worker.worker1"));

    Assert.assertTrue(readPolicy.isAllowed(ImmutableList.of(new Namespace("ns1"),
                                                            new Application("app1"),
                                                            new Program("worker.worker1")),
                                           new ActionFactory.Action("execute")));

    Assert.assertFalse(readPolicy.isAllowed(ImmutableList.of(new Dataset("app1")),
                                           new ActionFactory.Action("execute")));
    Assert.assertFalse(readPolicy.isAllowed(ImmutableList.of(new Namespace("ns2"),
                                                            new Application("app1"),
                                                            new Program("worker.worker1")),
                                           new ActionFactory.Action("execute")));
  }

  @Test
  public void testVisibility() {
    // Test entity and its ancestors are visible
    WildcardPolicy dsPolicy = createPolicy("read",
                                           toAuth("namespace", "ns1"),
                                           toAuth("dataset", "table"));
    WildcardPolicy appPolicy = createPolicy("execute",
                                            toAuth("namespace", "ns2"),
                                            toAuth("application", "app1"),
                                            toAuth("program", "worker.worker1"));
    WildcardPolicy nsPolicy = createPolicy("read", toAuth("namespace", "ns3"));

    // Test dsPolicy
    Assert.assertTrue(dsPolicy.isVisible(ImmutableList.of(new Namespace("ns1"))));
    Assert.assertFalse(dsPolicy.isVisible(ImmutableList.of(new Namespace("ns2"))));

    Assert.assertTrue(dsPolicy.isVisible(ImmutableList.of(new Namespace("ns1"), new Dataset("table"))));
    Assert.assertFalse(dsPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Dataset("table"))));
    Assert.assertFalse(dsPolicy.isVisible(ImmutableList.of(new Namespace("ns1"), new Dataset("index"))));
    Assert.assertFalse(dsPolicy.isVisible(ImmutableList.of(new Namespace("ns1"), new Application("app1"))));

    // Test appPolicy
    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns1"))));

    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app2"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns1"), new Application("app1"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns1"), new Application("app11"))));

    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                         new Program("worker.worker1"))));
    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                         new Program("Worker.worker1"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                         new Program("worker.worker2"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns1"), new Application("app1"),
                                                          new Program("worker.worker1"))));

    // Test nsPolicy
    Assert.assertTrue(nsPolicy.isVisible(ImmutableList.of(new Namespace("ns3"))));
    Assert.assertFalse(nsPolicy.isVisible(ImmutableList.of(new Namespace("ns2"))));
    Assert.assertFalse(nsPolicy.isVisible(ImmutableList.of(new Namespace("ns3"), new Application("app2"))));
    Assert.assertFalse(nsPolicy.isVisible(ImmutableList.of(new Namespace("ns3"), new Dataset("table"))));
  }

  @Test
  public void testWildcardVisibility() {
    WildcardPolicy appPolicy = createPolicy("execute",
                                            toAuth("namespace", "ns2"),
                                            toAuth("application", "app1"),
                                            toAuth("program", "worker.*"));

    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns1"))));

    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app2"))));

    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                           new Program("worker.worker2"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                           new Program("service.service1"))));
  }

  private static Authorizable toAuth(String type, String name) {
    return ModelAuthorizables.from(type, name);
  }

  private static WildcardPolicy createPolicy(String action, Authorizable... authorizables) {
    return new WildcardPolicy(Lists.newArrayList(authorizables), new ActionFactory.Action(action));
  }
}
