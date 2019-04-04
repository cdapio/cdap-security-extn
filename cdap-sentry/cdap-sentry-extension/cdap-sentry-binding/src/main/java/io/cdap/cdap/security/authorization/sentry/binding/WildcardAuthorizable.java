/*
 * Copyright © 2017-2019 Cask Data, Inc.
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

package io.cdap.cdap.security.authorization.sentry.binding;

import io.cdap.cdap.security.authorization.sentry.model.Authorizable;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * This class supports wildcard matching of {@link Authorizable}s.
 * "*" and "?" are the supported wildcards, "*" matches any number of characters and "?" matches one character.
 */
class WildcardAuthorizable {
  // TODO: can type have wildcards in it?
  // Type is case insensitive
  private final String type;
  // TODO: can sub-type have wildcards in it?
  // Sub type is case insensitive
  @Nullable
  private final String subType;
  // Name is case sensitive, and only * and ? are allowed as wildcards in the name pattern
  private final Pattern namePattern;

  WildcardAuthorizable(Authorizable authorizable) {
    this.type = authorizable.getTypeName();
    this.subType = authorizable.getSubType();

    // Only * and ? are allowed to be wildcards in the pattern, everything else should be matched literally
    this.namePattern = Pattern.compile(Pattern.quote(authorizable.getName())
                                         .replace("*", "\\E.*\\Q")
                                         .replace("?", "\\E.\\Q"));
  }

  boolean matches(Authorizable authorizable) {
    if (authorizable == null || authorizable.getName() == null) {
      return false;
    }

    if (subType != null && !subType.equalsIgnoreCase(authorizable.getSubType())) {
      return false;
    }

    Matcher matcher = namePattern.matcher(authorizable.getName());
    return type.equalsIgnoreCase(authorizable.getTypeName()) && matcher.matches();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    WildcardAuthorizable that = (WildcardAuthorizable) o;
    return Objects.equals(type, that.type) &&
      Objects.equals(subType, that.subType) &&
      Objects.equals(namePattern.toString(), that.namePattern.toString());
  }

  @Override
  public int hashCode() {
    return Objects.hash(type, subType, namePattern.toString());
  }

  @Override
  public String toString() {
    return "WildcardAuthorizable{" +
      "type='" + type + '\'' +
      ", subType='" + subType + '\'' +
      ", namePattern=" + namePattern +
      '}';
  }
}
