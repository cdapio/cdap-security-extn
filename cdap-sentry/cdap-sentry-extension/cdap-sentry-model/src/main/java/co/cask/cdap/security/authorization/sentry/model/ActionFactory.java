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

import org.apache.sentry.core.common.BitFieldAction;
import org.apache.sentry.core.common.BitFieldActionFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Factory for creating actions supported by CDAP.
 */
public class ActionFactory extends BitFieldActionFactory {

  /**
   * Types of supported actions.
   */
  public enum ActionType {
    READ(ActionConstant.READ, 1),
    WRITE(ActionConstant.WRITE, 2),
    EXECUTE(ActionConstant.EXECUTE, 4),
    ADMIN(ActionConstant.ADMIN, 8),
    ALL(ActionConstant.ALL, READ.getCode() | WRITE.getCode() | EXECUTE.getCode() | ADMIN.getCode());

    private final String name;
    private final int code;

    /**
     * Creates an action type based on provided action name and code.
     *
     * @param name Name of action.
     * @param code Integer representation of action's code.
     */
    ActionType(String name, int code) {
      this.name = name;
      this.code = code;
    }

    /**
     * Get code for this action.
     *
     * @return Code for this action.
     */
    public int getCode() {
      return code;
    }

    /**
     * Get name of this action.
     *
     * @return Name of this action.
     */
    public String getName() {
      return name;
    }

    /**
     * Gets an {@link ActionType} for the given action
     *
     * @param name String representation of the action
     * @return {@link ActionType} for the given action name
     * @throws RuntimeException if an {@link ActionType} is not found for the given action.
     */
    static ActionType getActionByName(String name) {
      for (ActionType action : ActionType.values()) {
        if (action.name.equalsIgnoreCase(name)) {
          return action;
        }
      }
      throw new RuntimeException("Can't get CDAP action by name:" + name);
    }

    /**
     * Creates a {@link List} of {@link ActionType} for the given action code.
     * Its a list since {@link ActionType#ALL} has more than one {@link ActionType}
     *
     * @param code Integer representation of {@link ActionType}
     * @return {@link List} of {@link ActionType} represented by the given code, if no action types are found returns
     * an empty list.
     */
    static List<ActionType> getActionByCode(int code) {
      List<ActionType> actions = new ArrayList<>();
      for (ActionType action : ActionType.values()) {
        if (((action.code & code) == action.code) && (action != ActionType.ALL)) {
          // ActionType.ALL action should not return in the list but its consisting ActionTypes should
          actions.add(action);
        }
      }
      return actions;
    }
  }

  /**
   * {@link Action} class which uses {@link BitFieldAction}. The bit field representation helps in comparison
   * specially for {@link ActionType#ALL} which is an 'or' of different ActionTypes
   */
  public static class Action extends BitFieldAction {
    /**
     * Creates an {@link Action} for the given action name
     *
     * @param name Name of the action.
     */
    public Action(String name) {
      this(ActionType.getActionByName(name));
    }

    /**
     * Create an {@link Action} for the given {@link ActionType}
     *
     * @param actionType {@link ActionType} for which the {@link Action} needs to created
     */
    public Action(ActionType actionType) {
      super(actionType.name(), actionType.getCode());
    }
  }

  /**
   * Gets a {@link List} of {@link Action} for the given action code
   *
   * @param actionCode Integer code for required actions.
   * @return {@link List} of {@link Action} for the given action code
   * @throws RuntimeException if no {@link Action} is found for the given name
   */
  @Override
  public List<Action> getActionsByCode(int actionCode) {
    List<Action> actions = new ArrayList<>();
    for (ActionType action : ActionType.getActionByCode(actionCode)) {
      actions.add(new Action(action));
    }
    return actions;
  }

  /**
   * Gets {@link Action} for the given name
   *
   * @param name of the required {@link Action}
   * @return {@link Action} for the given name if one exists
   * @throws RuntimeException if no {@link Action} is found for the given name
   */
  @Override
  public Action getActionByName(String name) {
    if ("*".equals(name)) {
      return new Action(ActionType.ALL);
    }
    return new Action(name);
  }
}
