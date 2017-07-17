package co.cask.cdap.security.authorization.sentry.binding;

import org.apache.sentry.core.common.Authorizable;
import org.apache.sentry.provider.db.generic.service.thrift.TAuthorizable;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 *
 */
class WildcardAuthorizable {
  // TODO: can type have wildcards in it?
  // Type is case insensitive
  private final String type;
  // Sub type is case insensitive
  @Nullable
  private final String subType;
  // Name is case sensitive, and only * and ? are allowed as wildcards in the name pattern
  private final Pattern namePattern;

  WildcardAuthorizable(TAuthorizable authorizable) {
    this.type = authorizable.getType();

    // Handle case insensitive program type matching
    String name;
    if (type.equalsIgnoreCase(co.cask.cdap.security.authorization.sentry.model.Authorizable.AuthorizableType.PROGRAM.toString())) {
      String[] split = authorizable.getName().split(".", 2);
      subType = split[0];
      name = split[1];
    } else {
      subType = null;
      name = authorizable.getName();
    }

    // Only * and ? are allowed to be wildcards in the pattern, everything else should be matched literally
    this.namePattern = Pattern.compile(Pattern.quote(name)
                                         .replace("*", "\\E.*\\Q")
                                         .replace("?", "\\E.\\Q"));
  }

  boolean matches(Authorizable authorizable) {
    if (authorizable == null || authorizable.getName() == null) {
      return false;
    }

    String sType;
    String name;
    if (authorizable.getTypeName().equalsIgnoreCase(co.cask.cdap.security.authorization.sentry.model.Authorizable.AuthorizableType.PROGRAM.toString())) {
      String[] split = authorizable.getName().split(".", 2);
      sType = split[0];
      name = split[1];
    } else {
      sType = null;
      name = authorizable.getName();
    }

    if (subType != null && !subType.equalsIgnoreCase(sType)) {
      return false;
    }

    Matcher matcher = namePattern.matcher(name);
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
      Objects.equals(namePattern.toString(), that.namePattern.toString());
  }

  @Override
  public int hashCode() {
    return Objects.hash(type, namePattern.toString());
  }

  @Override
  public String toString() {
    return "WildcardAuthorizable{" +
      "type='" + type + '\'' +
      ", namePattern=" + namePattern +
      '}';
  }
}
