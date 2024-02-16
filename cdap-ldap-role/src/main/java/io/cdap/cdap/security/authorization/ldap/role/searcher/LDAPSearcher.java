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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;


/**
 * Service for searching user's groups in LDAP
 */
public class LDAPSearcher {
  private static final Logger LOG = LoggerFactory.getLogger(LDAPSearcher.class);

  private final LDAPSearchConfig config;
  private final String[] baseDNList;
  private final LDAPClient client;

  /**
   * Constructor
   *
   * @param config {@link LDAPSearchConfig} configuration for LDAP searcher
   * @param client {@link LDAPClient} implementation for communication with LDAP
   */
  public LDAPSearcher(LDAPSearchConfig config, LDAPClient client) {
    this.config = config;
    this.client = client;
    baseDNList = config.getSearchBaseDn().split(LDAPConstants.BASE_DN_SPLITTER);
  }

  /**
   * Searches for groups by username
   *
   * @param username Name of user
   * @return Set of groups
   */
  public Set<String> searchGroups(String username) {
    for (int i = 1;; i++) {
      try {
        DirContext context = client.getConnection();

        SearchControls controls = new SearchControls();
        if (config.isRecursiveSearch()) {
          controls.setSearchScope(SUBTREE_SCOPE);
        }

        // Close of DirContext can also throw NamingException
        try {
          return Arrays.stream(baseDNList)
            .map(baseDN -> searchGroups(baseDN, username, context, controls))
            .flatMap(Collection::stream)
            .collect(Collectors.toSet());
        } finally {
          context.close();
        }
      } catch (NamingException e) {
        String errorMsg = String.format("Failed to find groups for user '%s'", username);

        // Throw error if maximum of attempts is reached
        if (i == LDAPConstants.MAX_SEARCH_RETRIES) {
          throw new RuntimeException(errorMsg, e);
        }

        LOG.warn(errorMsg, e);
        sleep(i * LDAPConstants.DEFAULT_RETRY_INTERVAL);
      }
    }
  }

  private Set<String> searchGroups(String baseDN, String username, DirContext context, SearchControls controls) {
    String filter = String.format(config.getSearchFilter(), username);
    Set<String> groups = new HashSet<>();

    try {
      NamingEnumeration<SearchResult> renum = context.search(baseDN, filter, controls);

      if (!renum.hasMore()) {
        LOG.debug("Cannot locate user information for '{}' in '{}'", username, baseDN);
        return groups;
      }

      SearchResult result = renum.next();

      Attribute memberOf = result.getAttributes().get(config.getMemberAttribute());
      if (memberOf != null) {
        for (int i = 0; i < memberOf.size(); i++) {
          groups.add(memberOf.get(i).toString());
        }
      }
    } catch (PartialResultException e) {
      LOG.debug("Failed to find groups for '{}' in '{}'", username, baseDN);
    } catch (NamingException e) {
      String errorMsg = String.format("Failed to find groups for '%s' in '%s'", username, baseDN);
      throw new RuntimeException(errorMsg, e);
    }

    return groups;
  }

  private void sleep(long time) {
    try {
      Thread.sleep(time);
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
    }
  }
}
