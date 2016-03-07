/*
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
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import org.apache.sentry.policy.common.KeyValue;
import org.apache.sentry.policy.common.PolicyConstants;
import org.apache.sentry.policy.common.Privilege;
import org.apache.sentry.policy.common.PrivilegeFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Wildcard Privilege class
 */
public class WildcardPrivilege implements Privilege {

  private final List<KeyValue> privilegeParts;

  public WildcardPrivilege(String permission) {
    if (Strings.isNullOrEmpty(permission)) {
      throw new IllegalArgumentException("Permission string cannot be null or empty.");
    }
    List<KeyValue> parts = new ArrayList<>();
    for (String authorizable : PolicyConstants.AUTHORIZABLE_SPLITTER.trimResults().split(permission.trim())) {
      if (authorizable.isEmpty()) {
        throw new IllegalArgumentException("Privilege '" + permission + "' has an empty section");
      }
      parts.add(new KeyValue(authorizable));
    }
    Preconditions.checkState(!parts.isEmpty(), String.format("Failed to split the permission string %s into a list of" +
                                                               " Authorizables separated by %s", permission,
                                                             PolicyConstants.AUTHORIZABLE_SPLITTER));
    this.privilegeParts = Collections.unmodifiableList(parts);
  }

  @Override
  public boolean implies(Privilege otherPrivilege) {
    if (this == otherPrivilege) {
      return true;
    }
    if (!(otherPrivilege instanceof WildcardPrivilege)) {
      return false;
    }
    WildcardPrivilege wp = (WildcardPrivilege) otherPrivilege;
    List<KeyValue> otherParts = wp.privilegeParts;
    int index = 0;
    for (KeyValue otherPart : otherParts) {
      // If this privilege has less parts than the other privilege, everything after the number of parts contained
      // in this privilege is automatically implied, so return true
      if (privilegeParts.size() - 1 < index) {
        return true;
      } else {
        KeyValue part = privilegeParts.get(index);
        if (!part.getKey().equalsIgnoreCase(otherPart.getKey()) || !impliesKeyValue(part, otherPart)) {
          return false;
        }
        index++;
      }
    }
    // If this privilege has more parts than the other parts (otherPrivilege), only imply it if all of the other
    // parts are "*" or "ALL"
    for (; index < privilegeParts.size(); index++) {
      KeyValue part = privilegeParts.get(index);
      if (!part.getValue().equals(ActionConstant.ALL)) {
        return false;
      }
    }
    return true;
  }

  private boolean impliesKeyValue(KeyValue policyPart, KeyValue requestPart) {
    Preconditions.checkState(policyPart.getKey().equalsIgnoreCase(requestPart.getKey()),
                             String.format("Privilege Key Mismatch: Key %s and %s does not match.", policyPart.getKey
                               (), requestPart.getKey()));
    if (policyPart.getValue().equalsIgnoreCase(ActionConstant.ALL) || policyPart.equals(requestPart)) {
      return true;
    } else if (!ActionConstant.ACTION_NAME.equalsIgnoreCase(policyPart.getKey()) &&
      ActionConstant.ALL.equalsIgnoreCase(requestPart.getValue())) {
      /* privilege request is to match with any object of given type */
      return true;
    }
    return false;
  }

  /**
   * Wildcard privilege factory
   */
  public static class Factory implements PrivilegeFactory {
    @Override
    public Privilege createPrivilege(String permission) {
      return new WildcardPrivilege(permission);
    }
  }
}
