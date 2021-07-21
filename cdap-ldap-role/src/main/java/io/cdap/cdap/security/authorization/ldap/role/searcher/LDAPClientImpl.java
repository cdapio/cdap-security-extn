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

import java.util.Hashtable;
import java.util.Objects;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

/**
 * Implementation of {@link LDAPClient} to communicate with LDAP
 */
public class LDAPClientImpl implements LDAPClient {
    private static final Logger LOG = LoggerFactory.getLogger(LDAPClientImpl.class);

    private final Hashtable<String, String> properties;
    private final LDAPSearchConfig config;

    public LDAPClientImpl(LDAPSearchConfig config) {
        this.config = config;
        properties = getConnectionProperties();
    }

    @Override
    public DirContext getConnection() throws NamingException {
        for (int i = 1;; i++) {
            try {
                return new InitialDirContext(properties);
            } catch (NamingException e) {
                LOG.warn("Failed connect to '{}' on attempt '{}'", config.getUrl(), i);

                // Throw error if maximum of attempts is reached
                if (i == LDAPConstants.MAX_CONNECTION_RETRIES) {
                    throw e;
                }

                sleep(i * LDAPConstants.DEFAULT_RETRY_INTERVAL);
            }
        }
    }

    @Override
    public void testConnection() {
        try {
            DirContext context = getConnection();
            context.close();
        } catch (NamingException e) {
            String errorMsg = String.format("Failed to establish connection to '%s'", config.getUrl());
            throw new RuntimeException(errorMsg, e);
        }
    }

    private Hashtable<String, String> getConnectionProperties() {
        Hashtable<String, String> props = new Hashtable<>();
        String url = config.getUrl();

        props.put(Context.SECURITY_PRINCIPAL, config.getLookUpBindDN());
        props.put(Context.SECURITY_CREDENTIALS, config.getLookUpBindPassword());
        props.put(Context.INITIAL_CONTEXT_FACTORY, LDAPConstants.LDAP_CONTEXT_FACTORY);
        props.put(Context.PROVIDER_URL, url);

        if (config.isIgnoreSSLVerify() && url.startsWith(LDAPConstants.LDAPS_PROTOCOL)) {
            props.put(LDAPConstants.LDAP_SOCKET_FACTORY, InsecureSSLSocketFactory.class.getName());
        }

        props.put(LDAPConstants.LDAP_POOL, "true");
        setPropertyIfNotNull(LDAPConstants.LDAP_POOL_AUTHENTICATION, config.getPoolAuthentication(), properties);
        setPropertyIfNotNull(LDAPConstants.LDAP_POOL_DEBUG, config.getPoolDebug(), properties);
        setPropertyIfNotNull(LDAPConstants.LDAP_POOL_MAXSIZE, config.getPoolMaxsize(), properties);
        setPropertyIfNotNull(LDAPConstants.LDAP_POOL_INITSIZE, config.getPoolInitsize(), properties);
        setPropertyIfNotNull(LDAPConstants.LDAP_POOL_PREFSIZE, config.getPoolPrefsize(), properties);
        setPropertyIfNotNull(LDAPConstants.LDAP_POOL_PROTOCOL, config.getPoolProtocol(), properties);
        setPropertyIfNotNull(LDAPConstants.LDAP_POOL_TIMEOUT, config.getPoolTimeout(), properties);

        return props;
    }

    private static void setPropertyIfNotNull(String propertyName, String propertyValue, Hashtable<String,
            String> properties) {
        if (Objects.nonNull(propertyValue)) {
            properties.put(propertyName, propertyValue);
        }
    }

    private void sleep(long time) {
        try {
            Thread.sleep(time);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }
}
