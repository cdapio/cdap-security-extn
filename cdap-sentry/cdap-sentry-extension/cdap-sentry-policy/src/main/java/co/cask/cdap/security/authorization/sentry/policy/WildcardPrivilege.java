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
import co.cask.cdap.security.authorization.sentry.model.ActionFactory.Action;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import org.apache.sentry.policy.common.KeyValue;
import org.apache.sentry.policy.common.PolicyConstants;
import org.apache.sentry.policy.common.Privilege;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
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
    for (String authorizable : PolicyConstants.AUTHORIZABLE_SPLITTER.trimResults().split(permission)) {
      if (authorizable.isEmpty()) {
        throw new IllegalArgumentException("Privilege '" + permission + "' has an empty section");
      }
      parts.add(new KeyValue(authorizable));
    }
    Preconditions.checkState(!parts.isEmpty(), "Failed to split the permission string %s into a list of Authorizables" +
      " separated by %s", permission, PolicyConstants.AUTHORIZABLE_SPLITTER);
    this.privilegeParts = Collections.unmodifiableList(parts);
  }

  @Override
  public boolean implies(Privilege requestPrivilege) {
    if (!(requestPrivilege instanceof WildcardPrivilege)) {
      return false;
    }
    WildcardPrivilege requestWildcardPrivilege = (WildcardPrivilege) requestPrivilege;
    List<KeyValue> requestParts = requestWildcardPrivilege.privilegeParts;
    if (this == requestWildcardPrivilege || equals(requestWildcardPrivilege)) {
      return true;
    }
    int index = 0;
    for (KeyValue requestPart : requestParts) {
      // If policy has less parts than the request, everything after the number of parts contained
      // in the policy is automatically implied, so return true
      if (privilegeParts.size() - 1 < index) {
        return true;
      }
      KeyValue policyPart = privilegeParts.get(index);
      // If we've reached the action in the current policy part but request privilege has more non-action parts, then
      // continue till we've reached the action in the request part. This also implies everything in the request part
      // policy part is implied.
      if (policyPart.getKey().equalsIgnoreCase(ActionConstant.ACTION_NAME)
        && !(requestPart.getKey().equalsIgnoreCase(ActionConstant.ACTION_NAME))) {
        continue;
      }
      // If the keys aren't equal, return false
      if (!policyPart.getKey().equalsIgnoreCase(requestPart.getKey())) {
        return false;
      }
      if (!impliesKeyValue(policyPart, requestPart)) {
        return false;
      }
      index++;
    }
    // If policy has more parts than the request, only imply it if all of the other parts are "*" or "ALL"
    for (; index < privilegeParts.size(); index++) {
      KeyValue part = privilegeParts.get(index);
      if (!part.getValue().equals(ActionConstant.ALL)) {
        return false;
      }
    }
    return true;
  }

  /**
   * For policy and request parts with the same key, ensure that the policy implies the request. In this method, the
   * keys for both #policyPart and #requestPart are expected to be the same.
   *
   * @param policyPart the policy part
   * @param requestPart the request part
   * @return true if either
   * - policy part is {@link Action#ALL}; or
   * - policy part equals request part;
   * false otherwise.
   */
  private boolean impliesKeyValue(KeyValue policyPart, KeyValue requestPart) {
    Preconditions.checkState(policyPart.getKey().equalsIgnoreCase(requestPart.getKey()),
                             String.format("Privilege Key Mismatch: Key %s and %s does not match.", policyPart.getKey
                               (), requestPart.getKey()));
    // if it is an action, then either the policy part must include ALL, or be the same as the request part.
    if (ActionConstant.ACTION_NAME.equalsIgnoreCase(policyPart.getKey()) &&
      policyPart.getValue().equalsIgnoreCase(ActionConstant.ALL)) {
        return true;
    }
    // if policy part is not Action#ALL, make sure that the policy and request parts match.
    return policyPart.equals(requestPart);
  }
}
