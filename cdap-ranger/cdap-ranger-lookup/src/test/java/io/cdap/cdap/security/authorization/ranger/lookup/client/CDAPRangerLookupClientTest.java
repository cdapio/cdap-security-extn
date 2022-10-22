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
package io.cdap.cdap.security.authorization.ranger.lookup.client;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.cdap.cdap.api.artifact.ArtifactSummary;
import io.cdap.cdap.client.ApplicationClient;
import io.cdap.cdap.client.NamespaceClient;
import io.cdap.cdap.proto.ApplicationDetail;
import io.cdap.cdap.proto.NamespaceMeta;
import io.cdap.cdap.proto.ProgramRecord;
import io.cdap.cdap.proto.ProgramType;
import io.cdap.cdap.proto.id.ApplicationId;
import io.cdap.cdap.security.authorization.ranger.commons.RangerCommon;
import org.apache.ranger.plugin.service.ResourceLookupContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.when;

/**
 * Test for {@link CDAPRangerLookupClient}
 */
public class CDAPRangerLookupClientTest {

  private NamespaceClient nsClient;
  private ApplicationClient applicationClient;
  private CDAPRangerLookupClient client;

  @Before
  public void before() throws IOException {
    // mock the clients
    nsClient = Mockito.mock(NamespaceClient.class);
    applicationClient = Mockito.mock(ApplicationClient.class);
    // we don't care about all clients and don't need to test all. We will test one in each hierarchy i.e. namespace,
    // streams (parent:namespace), program (parent:application)
    client = new CDAPRangerLookupClient("someinstance", "user", "password", nsClient, applicationClient,
                                        null, null, null, null, null);
  }

  @Test
  public void testNamespace() throws Exception {
    // prepare mock namespace result
    NamespaceMeta ns1Meta = new NamespaceMeta.Builder().setName("ns1").build();
    NamespaceMeta ns2Meta = new NamespaceMeta.Builder().setName("ns2").build();
    NamespaceMeta anotherNsMeta = new NamespaceMeta.Builder().setName("anotherNs").build();
    when(nsClient.list()).thenReturn(ImmutableList.of(ns1Meta, ns2Meta, anotherNsMeta));

    ResourceLookupContext resourceLookupContext = new ResourceLookupContext();
    resourceLookupContext.setResourceName("namespace");
    // user is entering n and we expect the completion to show ns1 and ns2 as they start with n and not anotherNs
    resourceLookupContext.setUserInput("n");
    resourceLookupContext.setResources(ImmutableMap.of("namespace", Collections.emptyList()));
    List<String> resources = client.getResources(resourceLookupContext);
    Assert.assertEquals(2, resources.size());
    Assert.assertEquals(ImmutableList.of("ns1", "ns2"), resources);
  }

  @Test
  public void testPrograms() throws Exception {
    // test programs specifically as they are one hierarchy down under application
    List<ProgramRecord> programRecords = ImmutableList.of(
      new ProgramRecord(ProgramType.WORKER, "dummyApp", "prog1", ""),
      new ProgramRecord(ProgramType.MAPREDUCE, "dummyApp", "prog2", ""),
      new ProgramRecord(ProgramType.MAPREDUCE, "dummyApp", "anotherProgram", ""));
    ApplicationDetail applicationDetail = new ApplicationDetail("name", ApplicationId.DEFAULT_VERSION, "desc", null, "config", null, programRecords,
                                                                null, new ArtifactSummary("art", "1"), null);
    when(applicationClient.get(new ApplicationId("dummyNs", "dummyApp"))).thenReturn(applicationDetail);

    ResourceLookupContext resourceLookupContext = new ResourceLookupContext();
    resourceLookupContext.setResourceName("program");
    resourceLookupContext.setUserInput("p");
    resourceLookupContext.setResources(ImmutableMap.of("namespace", ImmutableList.of("dummyNs"),
                                                       "application", ImmutableList.of("dummyApp")));
    List<String> resources = client.getResources(resourceLookupContext);
    Assert.assertEquals(2, resources.size());
    Assert.assertEquals(ImmutableList.of(
      Joiner.on(RangerCommon.RESOURCE_SEPARATOR).join(ProgramType.WORKER.getPrettyName().toLowerCase(), "prog1"),
      Joiner.on(RangerCommon.RESOURCE_SEPARATOR).join(ProgramType.MAPREDUCE.getPrettyName().toLowerCase(), "prog2")),
                        resources);
  }
}
