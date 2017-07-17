package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.security.authorization.sentry.model.ActionFactory;
import co.cask.cdap.security.authorization.sentry.model.Application;
import co.cask.cdap.security.authorization.sentry.model.Dataset;
import co.cask.cdap.security.authorization.sentry.model.Namespace;
import co.cask.cdap.security.authorization.sentry.model.Program;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TSentryPrivilege;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/**
 *
 */
public class WildcardPolicyTest {
  @Test
  public void testSimplePolicy() throws Exception {
    WildcardPolicy readPolicy = new WildcardPolicy(createPrivilege("read", tAuth("dataset", "table")));

    Assert.assertTrue(readPolicy.isAllowed(ImmutableList.of(new Dataset("table")), new ActionFactory.Action("read")));
    Assert.assertTrue(readPolicy.isAllowed(ImmutableList.of(new Dataset("table")), new ActionFactory.Action("READ")));

    Assert.assertFalse(readPolicy.isAllowed(ImmutableList.of(new Dataset("table")), new ActionFactory.Action("WRITE")));
    Assert.assertFalse(readPolicy.isAllowed(ImmutableList.of(new Dataset("Table")), new ActionFactory.Action("read")));
  }

  @Test
  public void testProgramPolicy() throws Exception {
    WildcardPolicy readPolicy = new WildcardPolicy(createPrivilege("execute",
                                                                   tAuth("namespace", "ns1"),
                                                                   tAuth("application", "app1"),
                                                                   tAuth("program", "Flow.flow1")));

    Assert.assertTrue(readPolicy.isAllowed(ImmutableList.of(new Namespace("ns1"),
                                                            new Application("app1"),
                                                            new Program("flow.flow1")),
                                           new ActionFactory.Action("execute")));

    Assert.assertFalse(readPolicy.isAllowed(ImmutableList.of(new Dataset("app1")),
                                           new ActionFactory.Action("execute")));
    Assert.assertFalse(readPolicy.isAllowed(ImmutableList.of(new Namespace("ns2"),
                                                            new Application("app1"),
                                                            new Program("flow.flow1")),
                                           new ActionFactory.Action("execute")));
  }

  @Test
  public void testVisibility() throws Exception {
    // Test entity and its ancestors are visible
    WildcardPolicy dsPolicy = new WildcardPolicy(createPrivilege("read",
                                                                tAuth("namespace", "ns1"),
                                                                tAuth("dataset", "table")));
    WildcardPolicy appPolicy = new WildcardPolicy(createPrivilege("execute",
                                                                tAuth("namespace", "ns2"),
                                                                tAuth("application", "app1"),
                                                                tAuth("program", "flow.flow1")));
    WildcardPolicy nsPolicy = new WildcardPolicy(createPrivilege("read", tAuth("namespace", "ns3")));

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
                                                         new Program("flow.flow1"))));
    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                         new Program("FloW.flow1"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                         new Program("flow.flow2"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns1"), new Application("app1"),
                                                          new Program("flow.flow1"))));

    // Test nsPolicy
    Assert.assertTrue(nsPolicy.isVisible(ImmutableList.of(new Namespace("ns3"))));
    Assert.assertFalse(nsPolicy.isVisible(ImmutableList.of(new Namespace("ns2"))));
    Assert.assertFalse(nsPolicy.isVisible(ImmutableList.of(new Namespace("ns3"), new Application("app2"))));
    Assert.assertFalse(nsPolicy.isVisible(ImmutableList.of(new Namespace("ns3"), new Dataset("table"))));
  }

  @Test
  public void testWildcardVisibility() throws Exception {
    WildcardPolicy appPolicy = new WildcardPolicy(createPrivilege("execute",
                                                                  tAuth("namespace", "ns2"),
                                                                  tAuth("application", "app1"),
                                                                  tAuth("program", "flow.*")));

    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns1"))));

    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app2"))));

    Assert.assertTrue(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                           new Program("flow.flow2"))));
    Assert.assertFalse(appPolicy.isVisible(ImmutableList.of(new Namespace("ns2"), new Application("app1"),
                                                           new Program("service.service1"))));
  }

  private static TAuthorizable tAuth(String type, String name) {
    return new TAuthorizable(type, name);
  }

  private static TSentryPrivilege createPrivilege(String action, TAuthorizable... authorizables) {
    List<TAuthorizable> tAuthorizables = Lists.newArrayList(authorizables);
    return new TSentryPrivilege("cdap", "cdap", tAuthorizables, action);
  }
}
