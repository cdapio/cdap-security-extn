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
  public boolean implies(Privilege otherPrivilege) {
    if (this == otherPrivilege) {
      return true;
    }
    if (!(otherPrivilege instanceof WildcardPrivilege)) {
      return false;
    }
    WildcardPrivilege wp = (WildcardPrivilege) otherPrivilege;

    Iterator<KeyValue> thisParts = privilegeParts.iterator();
    for (KeyValue otherPart : wp.privilegeParts) {
      // If this privilege has less parts than the other privilege, everything after the number of parts contained
      // in this privilege is automatically implied, so return true
      if (!thisParts.hasNext()) {
        return true;
      }

      KeyValue thisPart = thisParts.next();
      if (!thisPart.getKey().equalsIgnoreCase(otherPart.getKey()) || !impliesKeyValue(thisPart, otherPart)) {
        return false;
      }
    }
    // If this privilege has more parts than the other parts (otherPrivilege), only imply it if all of the other
    // parts are "*" or "ALL"
    while (thisParts.hasNext()) {
      if (!thisParts.next().getValue().equals(ActionConstant.ALL)) {
        return false;
      }
    }
    return true;
  }

  private boolean impliesKeyValue(KeyValue policyPart, KeyValue requestPart) {
    Preconditions.checkState(policyPart.getKey().equalsIgnoreCase(requestPart.getKey()),
                             String.format("Privilege Key Mismatch: Key %s and %s does not match.", policyPart.getKey
                               (), requestPart.getKey()));
    return policyPart.getValue().equalsIgnoreCase(ActionConstant.ALL) ||
      policyPart.equals(requestPart) ||
      (!ActionConstant.ACTION_NAME.equalsIgnoreCase(policyPart.getKey())
        && ActionConstant.ALL.equalsIgnoreCase(requestPart.getValue()));
  }
}
