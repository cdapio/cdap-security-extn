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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * An implementation of {@link SocketFactory} to ignore self signed certificates
 */
public class InsecureSSLSocketFactory extends SocketFactory {

  private static final SocketFactory INSTANCE = new InsecureSSLSocketFactory();

  private final SocketFactory socketFactory;

  private InsecureSSLSocketFactory() {
    TrustManager[] trustManagers = new TrustManager[]{
      new InsecureSSLTrustManager()
    };

    try {
      SSLContext sc = SSLContext.getInstance("SSL");
      sc.init(null, trustManagers, new SecureRandom());
      socketFactory = sc.getSocketFactory();
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to ignore SSL certificate", e);
    }
  }

  public static SocketFactory getDefault() {
    return INSTANCE;
  }

  @Override
  public Socket createSocket(String host, int port) throws IOException {
    return socketFactory.createSocket(host, port);
  }

  @Override
  public Socket createSocket(InetAddress address, int port) throws IOException {
    return socketFactory.createSocket(address, port);
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
    return socketFactory.createSocket(host, port, localHost, localPort);
  }

  @Override
  public Socket createSocket(InetAddress address, int port,
                             InetAddress localAddress, int localPort) throws IOException {
    return socketFactory.createSocket(address, port, localAddress, localPort);
  }
}
