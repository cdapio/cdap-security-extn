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

import com.google.common.collect.Lists;
import org.apache.sentry.core.common.BitFieldAction;
import org.apache.sentry.core.common.BitFieldActionFactory;

import java.util.Collections;
import java.util.List;

/**
 * Factory for creating actions supported by Kafka.
 */
public class ActionFactory extends BitFieldActionFactory {
  private static ActionFactory instance;

  private ActionFactory() {
  }

  /**
   * Get instance of {@link ActionFactory}, which is a singleton.
   *
   * @return Instance of KafkaActionFactory.
   */
  public static ActionFactory getInstance() {
    if (instance == null) {
      instance = new ActionFactory();
    }

    return instance;
  }

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
     * Create action type based on provided action and code.
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
     * Check if {@link ActionType} with the given name exists.
     *
     * @param name String representation of a valid action type.
     * @return true if {@link ActionType} with the given name exists.
     */
    static boolean hasActionType(String name) {
      for (ActionType action : ActionType.values()) {
        if (action.name.equalsIgnoreCase(name)) {
          return true;
        }
      }
      return false;
    }

    /**
     * Create {@link ActionType} for the given action
     *
     * @param name String representation of the action
     * @return {@link ActionType} for the given action name if one exists else null
     */
    static ActionType getActionByName(String name) {
      for (ActionType action : ActionType.values()) {
        if (action.name.equalsIgnoreCase(name)) {
          return action;
        }
      }
      return null; // Can't get ActionType of provided action
    }

    /**
     * Creates a {@link List} of {@link ActionType} for the given action code
     *
     * @param code Integer representation of {@link ActionType}
     * @return {@link List} of {@link ActionType} represented by the given code, if no action types are found returns
     * an empty list.
     */
    static List<ActionType> getActionByCode(int code) {
      List<ActionType> actions = Lists.newArrayList();
      for (ActionType action : ActionType.values()) {
        if (((action.code & code) == action.code) && (action != ActionType.ALL)) {
          // KafkaActionType.ALL action should not return in the list
          actions.add(action);
        }
      }
      if (actions.isEmpty()) {
        return Collections.emptyList();
      }
      return actions;
    }
  }

  /**
   * {@link Action} class which uses {@link BitFieldAction}
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
   * * @return {@link List} of {@link Action} for the given action code, if no {@link Action} is found then returns
   * a empty list
   */
  @Override
  public List<Action> getActionsByCode(int actionCode) {
    List<Action> actions = Lists.newArrayList();
    for (ActionType action : ActionType.getActionByCode(actionCode)) {
      actions.add(new Action(action));
    }
    return actions;
  }

  /**
   * Gets {@link Action} for the given name
   *
   * @param name of the required {@link Action}
   * @return {@link Action} for the given name if one exists else null
   */
  @Override
  public Action getActionByName(String name) {
    return ActionType.hasActionType(name) ? new Action(name) : null;
  }
}
