/*
 * Copyright © 2021-2022 Cask Data, Inc.
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

package io.cdap.cdap.security.authorization.ldap.role.searcher;

/**
 * Configuration for {@link LDAPSearcher}
 */
public class LDAPSearchConfig {
  private static final String DEFAULT_SEARCH_FILTER = "(&(objectClass=person)(samaccountname=%s))";
  private static final String DEFAULT_MEMBER_ATTRIBUTE = "memberOf";

  private String url;
  private String searchFilter;
  private String searchBaseDn;
  private String lookUpBindDN;
  private String memberAttribute;
  private String lookUpBindPassword;
  private boolean recursiveSearch;
  private boolean ignoreSSLVerify;

  // LDAP pool properties
  private String poolAuthentication;
  private String poolDebug;
  private String poolInitsize;
  private String poolMaxsize;
  private String poolPrefsize;
  private String poolProtocol;
  private String poolTimeout;

  public LDAPSearchConfig() {
  }

  public String getUrl() {
    return url;
  }

  public String getSearchFilter() {
    return searchFilter;
  }

  public String getSearchBaseDn() {
    return searchBaseDn;
  }

  public String getMemberAttribute() {
    return memberAttribute;
  }

  public boolean isRecursiveSearch() {
    return recursiveSearch;
  }

  public String getLookUpBindDN() {
    return lookUpBindDN;
  }

  public String getLookUpBindPassword() {
    return lookUpBindPassword;
  }

  public boolean isIgnoreSSLVerify() {
    return ignoreSSLVerify;
  }

  public String getPoolAuthentication() {
    return poolAuthentication;
  }

  public String getPoolDebug() {
    return poolDebug;
  }

  public String getPoolInitsize() {
    return poolInitsize;
  }

  public String getPoolMaxsize() {
    return poolMaxsize;
  }

  public String getPoolPrefsize() {
    return poolPrefsize;
  }

  public String getPoolProtocol() {
    return poolProtocol;
  }

  public String getPoolTimeout() {
    return poolTimeout;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public void setSearchFilter(String searchFilter) {
    if (searchFilter == null || searchFilter.isEmpty()) {
      this.searchFilter = DEFAULT_SEARCH_FILTER;
    } else {
      this.searchFilter = searchFilter;
    }
  }

  public void setSearchBaseDn(String searchBaseDn) {
    this.searchBaseDn = searchBaseDn;
  }

  public void setMemberAttribute(String memberAttribute) {
    if (memberAttribute == null || memberAttribute.isEmpty()) {
      this.memberAttribute = DEFAULT_MEMBER_ATTRIBUTE;
    } else {
      this.memberAttribute = memberAttribute;
    }
  }

  public void setRecursiveSearch(boolean recursiveSearch) {
    this.recursiveSearch = recursiveSearch;
  }

  public void setLookUpBindDN(String lookUpBindDN) {
    this.lookUpBindDN = lookUpBindDN;
  }

  public void setLookUpBindPassword(String lookUpBindPassword) {
    this.lookUpBindPassword = lookUpBindPassword;
  }

  public void setIgnoreSSLVerify(boolean ignoreSSLVerify) {
    this.ignoreSSLVerify = ignoreSSLVerify;
  }

  public void setPoolAuthentication(String poolAuthentication) {
    this.poolAuthentication = poolAuthentication;
  }

  public void setPoolDebug(String poolDebug) {
    this.poolDebug = poolDebug;
  }

  public void setPoolInitsize(String poolInitsize) {
    this.poolInitsize = poolInitsize;
  }

  public void setPoolMaxsize(String poolMaxsize) {
    this.poolMaxsize = poolMaxsize;
  }

  public void setPoolPrefsize(String poolPrefsize) {
    this.poolPrefsize = poolPrefsize;
  }

  public void setPoolProtocol(String poolProtocol) {
    this.poolProtocol = poolProtocol;
  }

  public void setPoolTimeout(String poolTimeout) {
    this.poolTimeout = poolTimeout;
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builder for {@link LDAPSearchConfig}
   */
  public static final class Builder {
    private String url;
    private String searchFilter;
    private String searchBaseDn;
    private String lookUpBindDN;
    private String memberAttribute;
    private String lookUpBindPassword;
    private boolean recursiveSearch;
    private boolean ignoreSSLVerify;
    private String poolAuthentication;
    private String poolDebug;
    private String poolInitsize;
    private String poolMaxsize;
    private String poolPrefsize;
    private String poolProtocol;
    private String poolTimeout;

    private Builder() {
    }

    public Builder withUrl(String url) {
      this.url = url;
      return this;
    }

    public Builder withSearchFilter(String searchFilter) {
      this.searchFilter = searchFilter;
      return this;
    }

    public Builder withSearchBaseDn(String searchBaseDn) {
      this.searchBaseDn = searchBaseDn;
      return this;
    }

    public Builder withLookUpBindDN(String lookUpBindDN) {
      this.lookUpBindDN = lookUpBindDN;
      return this;
    }

    public Builder withMemberAttribute(String memberAttribute) {
      this.memberAttribute = memberAttribute;
      return this;
    }

    public Builder withLookUpBindPassword(String lookUpBindPassword) {
      this.lookUpBindPassword = lookUpBindPassword;
      return this;
    }

    public Builder withRecursiveSearch(boolean recursiveSearch) {
      this.recursiveSearch = recursiveSearch;
      return this;
    }

    public Builder withIgnoreSSLVerify(boolean ignoreSSLVerify) {
      this.ignoreSSLVerify = ignoreSSLVerify;
      return this;
    }

    public Builder withPoolAuthentication(String poolAuthentication) {
      this.poolAuthentication = poolAuthentication;
      return this;
    }

    public Builder withPoolDebug(String poolDebug) {
      this.poolDebug = poolDebug;
      return this;
    }

    public Builder withPoolInitsize(String poolInitsize) {
      this.poolInitsize = poolInitsize;
      return this;
    }

    public Builder withPoolMaxsize(String poolMaxsize) {
      this.poolMaxsize = poolMaxsize;
      return this;
    }

    public Builder withPoolPrefsize(String poolPrefsize) {
      this.poolPrefsize = poolPrefsize;
      return this;
    }

    public Builder withPoolProtocol(String poolProtocol) {
      this.poolProtocol = poolProtocol;
      return this;
    }

    public Builder withPoolTimeout(String poolTimeout) {
      this.poolTimeout = poolTimeout;
      return this;
    }

    public LDAPSearchConfig build() {
      LDAPSearchConfig lDAPSearchConfig = new LDAPSearchConfig();
      lDAPSearchConfig.setUrl(url);
      lDAPSearchConfig.setSearchFilter(searchFilter);
      lDAPSearchConfig.setSearchBaseDn(searchBaseDn);
      lDAPSearchConfig.setLookUpBindDN(lookUpBindDN);
      lDAPSearchConfig.setMemberAttribute(memberAttribute);
      lDAPSearchConfig.setLookUpBindPassword(lookUpBindPassword);
      lDAPSearchConfig.setRecursiveSearch(recursiveSearch);
      lDAPSearchConfig.setIgnoreSSLVerify(ignoreSSLVerify);
      lDAPSearchConfig.setPoolAuthentication(poolAuthentication);
      lDAPSearchConfig.setPoolDebug(poolDebug);
      lDAPSearchConfig.setPoolInitsize(poolInitsize);
      lDAPSearchConfig.setPoolMaxsize(poolMaxsize);
      lDAPSearchConfig.setPoolPrefsize(poolPrefsize);
      lDAPSearchConfig.setPoolProtocol(poolProtocol);
      lDAPSearchConfig.setPoolTimeout(poolTimeout);
      return lDAPSearchConfig;
    }
  }
}


