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

import co.cask.cdap.security.authorization.sentry.model.ActionFactory.Action;
import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;


/**
 * Test for {@link ActionFactory}
 */
public class TestAction {
  private ActionFactory factory = ActionFactory.getInstance();

  @Test
  public void testImpliesAction() {
    Action readAction = factory.getActionByName(ActionConstant.READ);
    Action writeAction = factory.getActionByName(ActionConstant.WRITE);
    Action executeAction = factory.getActionByName(ActionConstant.EXECUTE);
    Action adminAction = factory.getActionByName(ActionConstant.ADMIN);
    Action allAction = factory.getActionByName(ActionConstant.ALL);

    Assert.assertTrue(allAction.implies(readAction));
    Assert.assertTrue(allAction.implies(writeAction));
    Assert.assertTrue(allAction.implies(executeAction));
    Assert.assertTrue(allAction.implies(adminAction));
    Assert.assertTrue(allAction.implies(allAction));

    Assert.assertTrue(readAction.implies(readAction));
    Assert.assertFalse(readAction.implies(writeAction));
    Assert.assertFalse(readAction.implies(executeAction));
    Assert.assertFalse(readAction.implies(adminAction));
    Assert.assertFalse(readAction.implies(allAction));

    Assert.assertFalse(writeAction.implies(readAction));
    Assert.assertTrue(writeAction.implies(writeAction));
    Assert.assertFalse(writeAction.implies(executeAction));
    Assert.assertFalse(writeAction.implies(adminAction));
    Assert.assertFalse(writeAction.implies(allAction));

    Assert.assertFalse(executeAction.implies(readAction));
    Assert.assertFalse(executeAction.implies(writeAction));
    Assert.assertTrue(executeAction.implies(executeAction));
    Assert.assertFalse(executeAction.implies(adminAction));
    Assert.assertFalse(executeAction.implies(allAction));

    Assert.assertFalse(adminAction.implies(readAction));
    Assert.assertFalse(adminAction.implies(writeAction));
    Assert.assertFalse(adminAction.implies(executeAction));
    Assert.assertTrue(adminAction.implies(adminAction));
    Assert.assertFalse(adminAction.implies(allAction));
  }

  @Test
  public void testGetActionByName() throws Exception {
    Action readAction = factory.getActionByName(ActionConstant.READ);
    Action writeAction = factory.getActionByName(ActionConstant.WRITE);
    Action executeAction = factory.getActionByName(ActionConstant.EXECUTE);
    Action adminAction = factory.getActionByName(ActionConstant.ADMIN);
    Action allAction = factory.getActionByName(ActionConstant.ALL);

    Assert.assertTrue(readAction.equals(new Action(ActionConstant.READ)));
    Assert.assertTrue(writeAction.equals(new Action(ActionConstant.WRITE)));
    Assert.assertTrue(executeAction.equals(new Action(ActionConstant.EXECUTE)));
    Assert.assertTrue(adminAction.equals(new Action(ActionConstant.ADMIN)));
    Assert.assertTrue(allAction.equals(new Action(ActionConstant.ALL)));
  }

  @Test
  public void testGetActionsByCode() throws Exception {
    Action readAction = new Action(ActionConstant.READ);
    Action writeAction = new Action(ActionConstant.WRITE);
    Action executeAction = factory.getActionByName(ActionConstant.EXECUTE);
    Action adminAction = factory.getActionByName(ActionConstant.ADMIN);
    Action allAction = new Action(ActionConstant.ALL);

    Assert.assertEquals(Lists.newArrayList(readAction),
                        factory.getActionsByCode(readAction.getActionCode()));
    Assert.assertEquals(Lists.newArrayList(writeAction),
                        factory.getActionsByCode(writeAction.getActionCode()));
    Assert.assertEquals(Lists.newArrayList(executeAction),
                        factory.getActionsByCode(executeAction.getActionCode()));
    Assert.assertEquals(Lists.newArrayList(adminAction),
                        factory.getActionsByCode(adminAction.getActionCode()));
    Assert.assertEquals(Lists.newArrayList(readAction, writeAction, executeAction, adminAction),
                        factory.getActionsByCode(allAction.getActionCode()));
  }

  @Test
  public void testGetActionForInvalidName() {
    Assert.assertNull(factory.getActionByName("INVALID"));
  }

  @Test
  public void testGetActionForInvalidCode() {
    Assert.assertEquals("Failed to NOT create actions for invalid code.", 0, factory.getActionsByCode(0).size());
  }
}
