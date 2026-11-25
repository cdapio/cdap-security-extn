/*
 * Copyright © 2026 Cask Data, Inc.
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

package org.apache.ranger.plugin.util;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.Writer;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * Unit tests for {@link RangerSslHelper}.
 */
public class RangerSslHelperTest {

  @Rule
  public TemporaryFolder tempFolder = new TemporaryFolder();

  @Test
  public void testHostnameVerifierRejectsUnverifiedSession() {
    RangerSslHelper helper = new RangerSslHelper("non-existent-ssl-config.xml");
    SSLSession unverifiedSession = (SSLSession) Proxy.newProxyInstance(
      SSLSession.class.getClassLoader(),
      new Class<?>[]{SSLSession.class},
      new InvocationHandler() {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
          if ("getPeerHost".equals(method.getName())) {
            return "ranger.example.com";
          }
          if ("getPeerCertificates".equals(method.getName())) {
            throw new SSLPeerUnverifiedException("peer not authenticated");
          }
          return null;
        }
      });

    Assert.assertFalse(helper.getHostnameVerifier().verify("ranger.example.com", unverifiedSession));
  }

  @Test
  public void testTlsContextAndContextClassLoaderResolution() throws Exception {
    Assert.assertEquals("TLS", RangerSslHelper.RANGER_SSL_CONTEXT_ALGO_TYPE);

    File resourceDir = tempFolder.newFolder("ssl-resources");
    char[] storePassword = "changeit".toCharArray();

    File keyStoreFile = new File(resourceDir, "test-keystore.jks");
    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(null, storePassword);
    try (FileOutputStream out = new FileOutputStream(keyStoreFile)) {
      ks.store(out, storePassword);
    }

    File trustStoreFile = new File(resourceDir, "test-truststore.jks");
    KeyStore ts = KeyStore.getInstance("JKS");
    ts.load(null, storePassword);
    try (FileOutputStream out = new FileOutputStream(trustStoreFile)) {
      ts.store(out, storePassword);
    }

    File jceksFile = new File(resourceDir, "creds.jceks");
    String credUrl = "jceks://file" + jceksFile.getAbsolutePath();
    Configuration credConf = new Configuration(false);
    credConf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH, credUrl);
    CredentialProvider provider = CredentialProviderFactory.getProviders(credConf).get(0);
    provider.createCredentialEntry(RangerSslHelper.RANGER_POLICYMGR_CLIENT_KEY_FILE_CREDENTIAL_ALIAS, storePassword);
    provider.createCredentialEntry(RangerSslHelper.RANGER_POLICYMGR_TRUSTSTORE_FILE_CREDENTIAL_ALIAS, storePassword);
    provider.flush();

    String sslConfigResource = "custom-context-cl-ranger-ssl.xml";
    File sslConfigFile = new File(resourceDir, sslConfigResource);
    Configuration sslConf = new Configuration(false);
    sslConf.set(RangerSslHelper.RANGER_POLICYMGR_CLIENT_KEY_FILE, "test-keystore.jks");
    sslConf.set(RangerSslHelper.RANGER_POLICYMGR_CLIENT_KEY_FILE_CREDENTIAL, credUrl);
    sslConf.set(RangerSslHelper.RANGER_POLICYMGR_TRUSTSTORE_FILE, "test-truststore.jks");
    sslConf.set(RangerSslHelper.RANGER_POLICYMGR_TRUSTSTORE_FILE_CREDENTIAL, credUrl);
    try (Writer writer = Files.newBufferedWriter(sslConfigFile.toPath(), StandardCharsets.UTF_8)) {
      sslConf.writeXml(writer);
    }

    ClassLoader originalCl = Thread.currentThread().getContextClassLoader();
    try (URLClassLoader customCl = new URLClassLoader(new URL[]{resourceDir.toURI().toURL()}, originalCl)) {
      Thread.currentThread().setContextClassLoader(customCl);
      RangerSslHelper helper = new RangerSslHelper(sslConfigResource);
      SSLContext sslContext = helper.createContext();
      Assert.assertNotNull(sslContext);
      Assert.assertEquals("TLS", sslContext.getProtocol());
    } finally {
      Thread.currentThread().setContextClassLoader(originalCl);
    }
  }
}
