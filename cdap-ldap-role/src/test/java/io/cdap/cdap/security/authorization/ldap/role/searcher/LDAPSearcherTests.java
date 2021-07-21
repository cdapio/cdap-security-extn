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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
 * Tests for {@link LDAPSearcher} class
 */
@RunWith(MockitoJUnitRunner.class)
public class LDAPSearcherTests {
    private final LDAPSearchConfig config = LDAPSearchConfig.builder()
            .withUrl("ldap://10.10.10.10:389/")
            .withSearchFilter("(&(objectClass=person)(samaccountname=%s))")
            .withSearchBaseDn("DC=test1,DC=local;DC=test2,DC=local")
            .withMemberAttribute("memberOf")
            .build();
    private final ArgumentCaptor<SearchControls> argumentCaptor = ArgumentCaptor.forClass(SearchControls.class);
    private final String username = "test";
    private final String filter = String.format(config.getSearchFilter(), username);

    @Mock
    private LDAPClient ldapClient;

    @Mock
    private DirContext dirContext;

    @Mock
    private NamingEnumeration<SearchResult> emptyAnswer;

    private LDAPSearcher searcher;

    @Before
    public void init() throws NamingException {
        Mockito.doReturn(emptyAnswer).when(dirContext).search(Mockito.anyString(), Mockito.eq(filter),
                argumentCaptor.capture());
        Mockito.doReturn(dirContext).when(ldapClient).getConnection();
        searcher = new LDAPSearcher(config, ldapClient);
    }

    @Test
    public void testNoGroups() {
        Set<String> groups = searcher.searchGroups(username);
        Assert.assertTrue(groups.isEmpty());
    }

    @Test
    public void testOneGroup() throws NamingException {
        Set<String> expectedGroups = new HashSet<>(setBaseDNMocks(1));

        Set<String> groups = searcher.searchGroups(username);
        Assert.assertEquals(expectedGroups, groups);
    }

    @Test
    public void testSeveralGroups() throws NamingException {
        List<String> groupsFromBaseDN1 = setBaseDNMocks(1);
        List<String> groupsFromBaseDN2 = setBaseDNMocks(2);

        Set<String> expectedGroups = Stream.concat(groupsFromBaseDN1.stream(), groupsFromBaseDN2.stream())
                .collect(Collectors.toSet());

        Set<String> groups = searcher.searchGroups(username);
        Assert.assertEquals(expectedGroups, groups);
    }

    private List<String> setBaseDNMocks(int groupsAmount) throws NamingException {
        String baseDN = String.format("DC=test%d,DC=local", groupsAmount);
        List<String> groups = IntStream.range(1, groupsAmount + 1)
                .mapToObj(number -> String.format("OU=group%d;%s", number, baseDN))
                .collect(Collectors.toList());

        NamingEnumeration<SearchResult> answerBaseDN1 = getAttributesAnswer(groups);
        Mockito.doReturn(answerBaseDN1).when(dirContext).search(Mockito.eq(baseDN), Mockito.eq(filter),
                argumentCaptor.capture());

        return groups;
    }

    private NamingEnumeration<SearchResult> getAttributesAnswer(List<String> groups) throws NamingException {
        @SuppressWarnings("unchecked")
        NamingEnumeration<SearchResult> answer = Mockito.mock(NamingEnumeration.class);
        Mockito.doReturn(true).when(answer).hasMore();

        SearchResult searchResult = Mockito.mock(SearchResult.class);
        Mockito.doReturn(searchResult).when(answer).next();

        Attributes attributes = Mockito.mock(Attributes.class);
        Mockito.doReturn(attributes).when(searchResult).getAttributes();

        Attribute attribute = Mockito.mock(Attribute.class);
        Mockito.doReturn(attribute).when(attributes).get(Mockito.eq(config.getMemberAttribute()));

        Mockito.doReturn(groups.size()).when(attribute).size();
        for (int i = 0; i < groups.size(); i++) {
            Mockito.doReturn(groups.get(i)).when(attribute).get(Mockito.eq(i));
        }

        return answer;
    }
}
