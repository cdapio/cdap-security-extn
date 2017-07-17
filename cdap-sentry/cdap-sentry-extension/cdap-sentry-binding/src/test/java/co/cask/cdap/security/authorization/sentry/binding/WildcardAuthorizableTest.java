package co.cask.cdap.security.authorization.sentry.binding;

import co.cask.cdap.security.authorization.sentry.model.Application;
import co.cask.cdap.security.authorization.sentry.model.Dataset;
import co.cask.cdap.security.authorization.sentry.model.Program;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 */
public class WildcardAuthorizableTest {
  @Test
  public void testAuthorizable() throws Exception {
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(new TAuthorizable("DATASET", "table"));
    Assert.assertTrue(dsAuth.matches(new Dataset("table")));

    Assert.assertFalse(dsAuth.matches(new Application("table")));
    Assert.assertFalse(dsAuth.matches(new Dataset("atableb")));
    Assert.assertFalse(dsAuth.matches(new Dataset("atable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("tables")));
    Assert.assertFalse(dsAuth.matches(new Dataset("Table")));
    Assert.assertFalse(dsAuth.matches(new Dataset("taable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("tabl*")));
    Assert.assertFalse(dsAuth.matches(new Dataset("able")));
    Assert.assertFalse(dsAuth.matches(new Dataset("tabl")));
    Assert.assertFalse(dsAuth.matches(new Dataset("")));
    Assert.assertFalse(dsAuth.matches(new Dataset(null)));
  }

  @Test
  public void testProgramAuthorizable() throws Exception {
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(new TAuthorizable("program", "flow.flow1"));
    Assert.assertTrue(dsAuth.matches(new Program("flow.flow1")));
    Assert.assertTrue(dsAuth.matches(new Program("FLOW.flow1")));

    Assert.assertFalse(dsAuth.matches(new Program("flow.Flow1")));
  }

  @Test
  public void testWildcardAuthorizable1() throws Exception {
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(new TAuthorizable("DATASET", "tab*"));
    Assert.assertTrue(dsAuth.matches(new Dataset("table")));
    Assert.assertTrue(dsAuth.matches(new Dataset("tabl*")));
    Assert.assertTrue(dsAuth.matches(new Dataset("tables")));
    Assert.assertTrue(dsAuth.matches(new Dataset("tabl")));
    Assert.assertTrue(dsAuth.matches(new Dataset("tab")));

    Assert.assertFalse(dsAuth.matches(new Application("table")));
    Assert.assertFalse(dsAuth.matches(new Dataset("atableb")));
    Assert.assertFalse(dsAuth.matches(new Dataset("atable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("ta*")));
    Assert.assertFalse(dsAuth.matches(new Dataset("Table")));
    Assert.assertFalse(dsAuth.matches(new Dataset("taable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("able")));
    Assert.assertFalse(dsAuth.matches(new Dataset("")));
    Assert.assertFalse(dsAuth.matches(new Dataset(null)));
  }

  @Test
  public void testWildcardAuthorizable2() throws Exception {
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(new TAuthorizable("dataset", "ta?le"));
    Assert.assertTrue(dsAuth.matches(new Dataset("table")));
    Assert.assertTrue(dsAuth.matches(new Dataset("tamle")));

    Assert.assertFalse(dsAuth.matches(new Dataset("tible")));
    Assert.assertFalse(dsAuth.matches(new Dataset("tabl*")));
    Assert.assertFalse(dsAuth.matches(new Dataset("atableb")));
    Assert.assertFalse(dsAuth.matches(new Dataset("atable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("tables")));
    Assert.assertFalse(dsAuth.matches(new Dataset("tabl")));
    Assert.assertFalse(dsAuth.matches(new Application("table")));
    Assert.assertFalse(dsAuth.matches(new Dataset("taable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("ta*")));
    Assert.assertFalse(dsAuth.matches(new Dataset("Table")));
    Assert.assertFalse(dsAuth.matches(new Dataset("able")));
    Assert.assertFalse(dsAuth.matches(new Dataset("")));
    Assert.assertFalse(dsAuth.matches(new Dataset(null)));
  }

  @Test
  public void testWildcardAuthorizable3() throws Exception {
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(new TAuthorizable("dataset", "*"));
    Assert.assertTrue(dsAuth.matches(new Dataset("table")));
    Assert.assertTrue(dsAuth.matches(new Dataset("12345")));
    Assert.assertTrue(dsAuth.matches(new Dataset("abcd")));
    Assert.assertTrue(dsAuth.matches(new Dataset("")));
    Assert.assertTrue(dsAuth.matches(new Dataset("null")));
  }

  @Test
  public void testQuoting() throws Exception {
    // \d and . should not match literally
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(new TAuthorizable("DATASET", "\\da?.*"));
    Assert.assertTrue(dsAuth.matches(new Dataset("\\dab.e")));
    Assert.assertTrue(dsAuth.matches(new Dataset("\\dam.es")));

    Assert.assertFalse(dsAuth.matches(new Dataset("\\dable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("\\dible")));
    Assert.assertFalse(dsAuth.matches(new Dataset("5able")));
    Assert.assertFalse(dsAuth.matches(new Dataset("dables")));
    Assert.assertFalse(dsAuth.matches(new Dataset("adableb")));
    Assert.assertFalse(dsAuth.matches(new Dataset("adable")));
    Assert.assertFalse(dsAuth.matches(new Application("dable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("daable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("Dable")));
    Assert.assertFalse(dsAuth.matches(new Dataset("")));
    Assert.assertFalse(dsAuth.matches(new Dataset(null)));
  }
}
