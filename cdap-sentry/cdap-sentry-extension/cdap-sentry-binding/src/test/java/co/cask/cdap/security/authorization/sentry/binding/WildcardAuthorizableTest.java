/*
 * Copyright © 2017 Cask Data, Inc.
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

import co.cask.cdap.security.authorization.sentry.model.Application;
import co.cask.cdap.security.authorization.sentry.model.Authorizable;
import co.cask.cdap.security.authorization.sentry.model.Dataset;
import co.cask.cdap.security.authorization.sentry.model.Program;
import co.cask.cdap.security.authorization.sentry.policy.ModelAuthorizables;
import org.junit.Assert;
import org.junit.Test;

/**
 * Tests {@link WildcardAuthorizable} with various cases.
 */
public class WildcardAuthorizableTest {
  @Test
  public void testAuthorizable() throws Exception {
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(toAuth("DATASET", "table"));
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
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(toAuth("program", "flow.flow1"));
    Assert.assertTrue(dsAuth.matches(new Program("flow.flow1")));
    Assert.assertTrue(dsAuth.matches(new Program("FLOW.flow1")));

    Assert.assertFalse(dsAuth.matches(new Program("flow.Flow1")));
  }

  @Test
  public void testWildcardAuthorizable1() throws Exception {
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(toAuth("DATASET", "tab*"));
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
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(toAuth("dataset", "ta?le"));
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
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(toAuth("dataset", "*"));
    Assert.assertTrue(dsAuth.matches(new Dataset("table")));
    Assert.assertTrue(dsAuth.matches(new Dataset("12345")));
    Assert.assertTrue(dsAuth.matches(new Dataset("abcd")));
    Assert.assertTrue(dsAuth.matches(new Dataset("")));
    Assert.assertTrue(dsAuth.matches(new Dataset("null")));
  }

  @Test
  public void testQuoting() throws Exception {
    // \d and . should not match literally
    WildcardAuthorizable dsAuth = new WildcardAuthorizable(toAuth("DATASET", "\\da?.*"));
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

  private static Authorizable toAuth(String type, String name) {
    return ModelAuthorizables.from(type, name);
  }

}
