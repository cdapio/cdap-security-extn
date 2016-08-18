package co.cask.cdap.security.authorization.ldap;

/**
 * This class holds information for LDAP search.
 */
final class SearchConfig {

  private final String baseDn;
  private final String objectClass;
  private final String memberAttribute;
  private final String nameAttribute;

  SearchConfig(String baseDn, String objectClass, String memberAttribute, String nameAttribute) {
    this.baseDn = baseDn;
    this.objectClass = objectClass;
    this.memberAttribute = memberAttribute;
    this.nameAttribute = nameAttribute;
  }

  String getBaseDn() {
    return baseDn;
  }

  String getObjectClass() {
    return objectClass;
  }

  String getMemberAttribute() {
    return memberAttribute;
  }

  String getNameAttribute() {
    return nameAttribute;
  }
}
