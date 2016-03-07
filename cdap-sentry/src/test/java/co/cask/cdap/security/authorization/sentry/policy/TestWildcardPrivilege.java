/*
 *
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

package co.cask.cdap.security.authorization.sentry.policy;

import co.cask.cdap.security.authorization.sentry.model.ActionConstant;
import org.apache.sentry.policy.common.KeyValue;
import org.apache.sentry.policy.common.PolicyConstants;
import org.apache.sentry.policy.common.Privilege;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test for {@link WildcardPrivilege}
 */
public class TestWildcardPrivilege {

  // instance
  private static final Privilege INSTANCE1_ALL =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("action", ActionConstant.ALL));
  private static final Privilege INSTANCE1_READ =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("action", ActionConstant.READ));
  private static final Privilege INSTANCE1_WRITE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("action", ActionConstant.WRITE));
  private static final Privilege INSTANCE1_EXECUTE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("action", ActionConstant.EXECUTE));
  private static final Privilege INSTANCE1_ADMIN =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("action", ActionConstant.ADMIN));

  // instance -> namespace
  private static final Privilege NAMESPACE1_ALL =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("action", ActionConstant.ALL));
  private static final Privilege NAMESPACE1_READ =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("action", ActionConstant.READ));
  private static final Privilege NAMESPACE1_WRITE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("action", ActionConstant.WRITE));
  private static final Privilege NAMESPACE1_EXECUTE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("action", ActionConstant.EXECUTE));
  private static final Privilege NAMESPACE1_ADMIN =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("action", ActionConstant.ADMIN));

  // instance -> namespace -> artifact
  private static final Privilege ARTIFACT1_ALL =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("ARTIFACT", "artifact1"), new KeyValue("action", ActionConstant.ALL));
  private static final Privilege ARTIFACT1_READ =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("ARTIFACT", "artifact1"), new KeyValue("action", ActionConstant.READ));
  private static final Privilege ARTIFACT1_WRITE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("ARTIFACT", "artifact1"), new KeyValue("action", ActionConstant.WRITE));
  private static final Privilege ARTIFACT1_EXECUTE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("ARTIFACT", "artifact1"), new KeyValue("action", ActionConstant.EXECUTE));
  private static final Privilege ARTIFACT1_ADMIN =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("ARTIFACT", "artifact1"), new KeyValue("action", ActionConstant.ADMIN));

  // instance -> namespace -> stream
  private static final Privilege STREAM1_ALL =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("STREAM", "stream1"), new KeyValue("action", ActionConstant.ALL));
  private static final Privilege STREAM1_READ =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("STREAM", "stream1"), new KeyValue("action", ActionConstant.READ));
  private static final Privilege STREAM1_WRITE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("STREAM", "stream1"), new KeyValue("action", ActionConstant.WRITE));
  private static final Privilege STREAM1_EXECUTE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("STREAM", "stream1"), new KeyValue("action", ActionConstant.EXECUTE));
  private static final Privilege STREAM1_ADMIN =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("STREAM", "stream1"), new KeyValue("action", ActionConstant.ADMIN));

  // instance -> namespace -> dataset
  private static final Privilege DATASET1_ALL =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("DATASET", "dataset1"), new KeyValue("action", ActionConstant.ALL));
  private static final Privilege DATASET1_READ =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("DATASET", "dataset1"), new KeyValue("action", ActionConstant.READ));
  private static final Privilege DATASET1_WRITE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("DATASET", "dataset1"), new KeyValue("action", ActionConstant.WRITE));
  private static final Privilege DATASET1_EXECUTE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("DATASET", "dataset1"), new KeyValue("action", ActionConstant.EXECUTE));
  private static final Privilege DATASET1_ADMIN =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("DATASET", "dataset1"), new KeyValue("action", ActionConstant.ADMIN));

  // instance -> namespace -> application
  private static final Privilege APPLICATION1_ALL =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("action", ActionConstant.ALL));
  private static final Privilege APPLICATION1_READ =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("action", ActionConstant.READ));
  private static final Privilege APPLICATION1_WRITE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("action", ActionConstant.WRITE));
  private static final Privilege APPLICATION1_EXECUTE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("action", ActionConstant.EXECUTE));
  private static final Privilege APPLICATION1_ADMIN =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("action", ActionConstant.ADMIN));

  // instance -> namespace -> application -> program
  private static final Privilege PROGRAM1_ALL =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("PROGRAM", "program1"),
           new KeyValue("action", ActionConstant.ALL));
  private static final Privilege PROGRAM1_READ =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("PROGRAM", "program1"),
           new KeyValue("action", ActionConstant.READ));
  private static final Privilege PROGRAM1_WRITE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("PROGRAM", "program1"),
           new KeyValue("action", ActionConstant.WRITE));
  private static final Privilege PROGRAM1_EXECUTE =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("PROGRAM", "program1"),
           new KeyValue("action", ActionConstant.EXECUTE));
  private static final Privilege PROGRAM1_ADMIN =
    create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"),
           new KeyValue("APPLICATION", "application1"), new KeyValue("PROGRAM", "program1"),
           new KeyValue("action", ActionConstant.ADMIN));

  private static WildcardPrivilege create(KeyValue... keyValues) {
    return create(PolicyConstants.AUTHORIZABLE_JOINER.join(keyValues));
  }

  private static WildcardPrivilege create(String s) {
    return new WildcardPrivilege(s);
  }

  @Test
  public void testActionAll() throws Exception {

    // instance
    assertTrue(INSTANCE1_ALL.implies(INSTANCE1_ALL));
    assertTrue(INSTANCE1_ALL.implies(INSTANCE1_ADMIN));
    assertTrue(INSTANCE1_ALL.implies(INSTANCE1_READ));

    // namespace
    assertTrue(NAMESPACE1_ALL.implies(NAMESPACE1_ALL));
    assertTrue(NAMESPACE1_ALL.implies(NAMESPACE1_ADMIN));
    assertTrue(NAMESPACE1_ALL.implies(NAMESPACE1_WRITE));

    // artifact
    assertTrue(ARTIFACT1_ALL.implies(ARTIFACT1_ALL));
    assertTrue(ARTIFACT1_ALL.implies(ARTIFACT1_ADMIN));
    assertTrue(ARTIFACT1_ALL.implies(ARTIFACT1_READ));

    // stream
    assertTrue(STREAM1_ALL.implies(STREAM1_ALL));
    assertTrue(STREAM1_ALL.implies(STREAM1_ADMIN));
    assertTrue(STREAM1_ALL.implies(STREAM1_WRITE));

    // dataset
    assertTrue(DATASET1_ALL.implies(DATASET1_ALL));
    assertTrue(DATASET1_ALL.implies(DATASET1_ADMIN));
    assertTrue(DATASET1_ALL.implies(DATASET1_READ));

    // application
    assertTrue(APPLICATION1_ALL.implies(APPLICATION1_ALL));
    assertTrue(APPLICATION1_ALL.implies(APPLICATION1_ADMIN));
    assertTrue(APPLICATION1_ALL.implies(APPLICATION1_WRITE));

    // program
    assertTrue(PROGRAM1_ALL.implies(PROGRAM1_ALL));
    assertTrue(PROGRAM1_ALL.implies(PROGRAM1_ADMIN));
    assertTrue(PROGRAM1_ALL.implies(PROGRAM1_EXECUTE));
  }

  @Test
  public void testSimpleAction() throws Exception {
    // instance
    assertFalse(INSTANCE1_READ.implies(INSTANCE1_WRITE));
    assertFalse(INSTANCE1_READ.implies(INSTANCE1_EXECUTE));
    assertFalse(INSTANCE1_READ.implies(INSTANCE1_ADMIN));
    assertFalse(INSTANCE1_READ.implies(INSTANCE1_ALL));

    // namespace
    assertFalse(NAMESPACE1_READ.implies(NAMESPACE1_WRITE));
    assertFalse(NAMESPACE1_READ.implies(NAMESPACE1_EXECUTE));
    assertFalse(NAMESPACE1_READ.implies(ARTIFACT1_ADMIN));
    assertFalse(NAMESPACE1_READ.implies(NAMESPACE1_ALL));

    // artifact
    assertFalse(ARTIFACT1_READ.implies(ARTIFACT1_WRITE));
    assertFalse(ARTIFACT1_READ.implies(ARTIFACT1_EXECUTE));
    assertFalse(ARTIFACT1_READ.implies(ARTIFACT1_ADMIN));
    assertFalse(ARTIFACT1_READ.implies(ARTIFACT1_ALL));

    // stream
    assertFalse(STREAM1_READ.implies(STREAM1_WRITE));
    assertFalse(STREAM1_READ.implies(STREAM1_EXECUTE));
    assertFalse(STREAM1_READ.implies(STREAM1_ADMIN));
    assertFalse(STREAM1_READ.implies(STREAM1_ALL));

    // dataset
    assertFalse(DATASET1_READ.implies(DATASET1_WRITE));
    assertFalse(DATASET1_READ.implies(DATASET1_EXECUTE));
    assertFalse(DATASET1_READ.implies(DATASET1_ADMIN));
    assertFalse(DATASET1_READ.implies(DATASET1_ALL));

    // application
    assertFalse(APPLICATION1_READ.implies(APPLICATION1_WRITE));
    assertFalse(APPLICATION1_READ.implies(APPLICATION1_EXECUTE));
    assertFalse(APPLICATION1_READ.implies(APPLICATION1_ADMIN));
    assertFalse(APPLICATION1_READ.implies(APPLICATION1_ALL));

    // program
    assertFalse(PROGRAM1_READ.implies(PROGRAM1_WRITE));
    assertFalse(PROGRAM1_READ.implies(PROGRAM1_EXECUTE));
    assertFalse(PROGRAM1_READ.implies(PROGRAM1_ADMIN));
    assertFalse(PROGRAM1_READ.implies(PROGRAM1_ALL));
  }

  @Test
  public void testUnexpected() throws Exception {
    Privilege p = new Privilege() {
      @Override
      public boolean implies(Privilege p) {
        return false;
      }
    };
    Privilege namespace1 = create(new KeyValue("INSTANCE", "instance1"), new KeyValue("NAMESPACE", "namespace1"));
    assertFalse(namespace1.implies(null));
    assertFalse(namespace1.implies(p));
    assertFalse(namespace1.equals(null));
    assertFalse(namespace1.equals(p));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullString() throws Exception {
    System.out.println(create((String) null));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyString() throws Exception {
    System.out.println(create(""));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyKey() throws Exception {
    System.out.println(create(PolicyConstants.KV_JOINER.join("", "EmptyKey")));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyValue() throws Exception {
    System.out.println(create(PolicyConstants.KV_JOINER.join("EmptyValue", "")));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testEmptyPart() throws Exception {
    System.out.println(create(PolicyConstants.AUTHORIZABLE_JOINER.
      join(PolicyConstants.KV_JOINER.join("INSTANCE", "instance1"), "")));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testOnlySeparators() throws Exception {
    System.out.println(create(PolicyConstants.AUTHORIZABLE_JOINER.
      join(PolicyConstants.KV_SEPARATOR, PolicyConstants.KV_SEPARATOR, PolicyConstants.KV_SEPARATOR)));
  }
}
