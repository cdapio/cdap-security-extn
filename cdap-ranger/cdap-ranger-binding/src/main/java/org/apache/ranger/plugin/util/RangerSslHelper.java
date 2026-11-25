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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.ranger.authorization.hadoop.utils.RangerCredentialProvider;
import org.apache.ranger.authorization.utils.StringUtil;

import com.google.common.base.MoreObjects;

public class RangerSslHelper {
	private static final Log LOG = LogFactory.getLog(RangerSslHelper.class);

	static final String RANGER_POLICYMGR_CLIENT_KEY_FILE                  = "xasecure.policymgr.clientssl.keystore";	
	static final String RANGER_POLICYMGR_CLIENT_KEY_FILE_TYPE             = "xasecure.policymgr.clientssl.keystore.type";
	static final String RANGER_POLICYMGR_CLIENT_KEY_FILE_CREDENTIAL       = "xasecure.policymgr.clientssl.keystore.credential.file";
	static final String RANGER_POLICYMGR_CLIENT_KEY_FILE_CREDENTIAL_ALIAS = "sslKeyStore";
	static final String RANGER_POLICYMGR_CLIENT_KEY_FILE_TYPE_DEFAULT     = "jks";	

	static final String RANGER_POLICYMGR_TRUSTSTORE_FILE                  = "xasecure.policymgr.clientssl.truststore";	
	static final String RANGER_POLICYMGR_TRUSTSTORE_FILE_TYPE             = "xasecure.policymgr.clientssl.truststore.type";	
	static final String RANGER_POLICYMGR_TRUSTSTORE_FILE_CREDENTIAL       = "xasecure.policymgr.clientssl.truststore.credential.file";
	static final String RANGER_POLICYMGR_TRUSTSTORE_FILE_CREDENTIAL_ALIAS = "sslTrustStore";
	static final String RANGER_POLICYMGR_TRUSTSTORE_FILE_TYPE_DEFAULT     = "jks";	

	static final String RANGER_SSL_KEYMANAGER_ALGO_TYPE                   = "SunX509";
	static final String RANGER_SSL_TRUSTMANAGER_ALGO_TYPE                 = "SunX509";
	static final String RANGER_SSL_CONTEXT_ALGO_TYPE                      = "TLS";

	private String mKeyStoreURL     = null;
	private String mKeyStoreAlias   = null;
	private String mKeyStoreFile    = null;
	private String mKeyStoreType    = null;
	private String mTrustStoreURL   = null;
	private String mTrustStoreAlias = null;
	private String mTrustStoreFile  = null;
	private String mTrustStoreType  = null;

	private static final HostnameVerifier hostnameVerifier = new HostnameVerifier() {
		@Override
		public boolean verify(String urlHostName, SSLSession session) {
			return HttpsURLConnection.getDefaultHostnameVerifier().verify(urlHostName, session);
		}
	};
	
	final String mSslConfigFileName;

	public RangerSslHelper(String sslConfigFileName) {
		mSslConfigFileName = sslConfigFileName;

		if(LOG.isDebugEnabled()) {
			LOG.debug("==> RangerSslHelper(" + mSslConfigFileName + ")");
		}

	}
	
	public SSLContext createContext() {
		readConfig();
		KeyManager[]   kmList     = getKeyManagers();
		TrustManager[] tmList     = getTrustManagers();
		SSLContext     sslContext = getSSLContext(kmList, tmList);
		return sslContext;
	}
	
	public HostnameVerifier getHostnameVerifier() {
		return hostnameVerifier;
	}
	
	void readConfig() {
		InputStream in =  null;

		try {
			Configuration conf = new Configuration();

			in = getFileInputStream(mSslConfigFileName);

			if (in != null) {
				conf.addResource(in);
			}

			mKeyStoreURL   = conf.get(RANGER_POLICYMGR_CLIENT_KEY_FILE_CREDENTIAL);
			mKeyStoreAlias = RANGER_POLICYMGR_CLIENT_KEY_FILE_CREDENTIAL_ALIAS;
			mKeyStoreType  = conf.get(RANGER_POLICYMGR_CLIENT_KEY_FILE_TYPE, RANGER_POLICYMGR_CLIENT_KEY_FILE_TYPE_DEFAULT);
			mKeyStoreFile  = conf.get(RANGER_POLICYMGR_CLIENT_KEY_FILE);

			mTrustStoreURL   = conf.get(RANGER_POLICYMGR_TRUSTSTORE_FILE_CREDENTIAL);
			mTrustStoreAlias = RANGER_POLICYMGR_TRUSTSTORE_FILE_CREDENTIAL_ALIAS;
			mTrustStoreType  = conf.get(RANGER_POLICYMGR_TRUSTSTORE_FILE_TYPE, RANGER_POLICYMGR_TRUSTSTORE_FILE_TYPE_DEFAULT);
			mTrustStoreFile  = conf.get(RANGER_POLICYMGR_TRUSTSTORE_FILE);

			if (LOG.isDebugEnabled()) {
				LOG.debug(MoreObjects.toStringHelper("RangerSslHelper")
					.add("keyStoreAlias", mKeyStoreAlias)
					.add("keyStoreFile", mKeyStoreFile)
					.add("keyStoreType", mKeyStoreType)
					.add("keyStoreURL", mKeyStoreURL)
					.add("trustStoreAlias", mTrustStoreAlias)
					.add("trustStoreFile", mTrustStoreFile)
					.add("trustStoreType", mTrustStoreType)
					.add("trustStoreURL", mTrustStoreURL)
					.toString());
			}
		}
		catch(IOException ioe) {
			LOG.error("Unable to load SSL Config FileName: [" + mSslConfigFileName + "]", ioe);
		}
		finally {
			close(in, mSslConfigFileName);
		}
	}
	
	private KeyManager[] getKeyManagers() {
		KeyManager[] kmList = null;

		char[] keyStoreFilepwd = getCredential(mKeyStoreURL, mKeyStoreAlias);

		try {
			if (!StringUtil.isEmpty(mKeyStoreFile) && keyStoreFilepwd != null && keyStoreFilepwd.length > 0) {
				InputStream in = null;

				try {
					in = getFileInputStream(mKeyStoreFile);

					if (in != null) {
						KeyStore keyStore = KeyStore.getInstance(mKeyStoreType);

						keyStore.load(in, keyStoreFilepwd);

						KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(RANGER_SSL_KEYMANAGER_ALGO_TYPE);

						keyManagerFactory.init(keyStore, keyStoreFilepwd);

						kmList = keyManagerFactory.getKeyManagers();
					} else {
						LOG.error("Unable to obtain keystore from file [" + mKeyStoreFile + "]");
					}
				} catch (KeyStoreException e) {
					LOG.error("Unable to obtain from KeyStore", e);
				} catch (NoSuchAlgorithmException e) {
					LOG.error("SSL algorithm is available in the environment", e);
				} catch (CertificateException e) {
					LOG.error("Unable to obtain the requested certification ", e);
				} catch (FileNotFoundException e) {
					LOG.error("Unable to find the necessary SSL Keystore and TrustStore Files", e);
				} catch (IOException e) {
					LOG.error("Unable to read the necessary SSL Keystore and TrustStore Files", e);
				} catch (UnrecoverableKeyException e) {
					LOG.error("Unable to recover the key from keystore", e);
				} finally {
					close(in, mKeyStoreFile);
				}
			}
		} finally {
			if (keyStoreFilepwd != null) {
				Arrays.fill(keyStoreFilepwd, '\0');
			}
		}

		return kmList;
	}

	private TrustManager[] getTrustManagers() {
		TrustManager[] tmList = null;

		char[] trustStoreFilepwd = getCredential(mTrustStoreURL, mTrustStoreAlias);

		try {
			if (!StringUtil.isEmpty(mTrustStoreFile) && trustStoreFilepwd != null && trustStoreFilepwd.length > 0) {
				InputStream in = null;

				try {
					in = getFileInputStream(mTrustStoreFile);

					if (in != null) {
						KeyStore trustStore = KeyStore.getInstance(mTrustStoreType);

						trustStore.load(in, trustStoreFilepwd);

						TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(RANGER_SSL_TRUSTMANAGER_ALGO_TYPE);

						trustManagerFactory.init(trustStore);

						tmList = trustManagerFactory.getTrustManagers();
					} else {
						LOG.error("Unable to obtain keystore from file [" + mTrustStoreFile + "]");
					}
				} catch (KeyStoreException e) {
					LOG.error("Unable to obtain from KeyStore", e);
				} catch (NoSuchAlgorithmException e) {
					LOG.error("SSL algorithm is available in the environment", e);
				} catch (CertificateException e) {
					LOG.error("Unable to obtain the requested certification ", e);
				} catch (FileNotFoundException e) {
					LOG.error("Unable to find the necessary SSL Keystore and TrustStore Files", e);
				} catch (IOException e) {
					LOG.error("Unable to read the necessary SSL Keystore and TrustStore Files", e);
				} finally {
					close(in, mTrustStoreFile);
				}
			}
		} finally {
			if (trustStoreFilepwd != null) {
				Arrays.fill(trustStoreFilepwd, '\0');
			}
		}
		
		return tmList;
	}
	
	private SSLContext getSSLContext(KeyManager[] kmList, TrustManager[] tmList) {
		try {
			if(kmList != null && tmList != null) {
				SSLContext sslContext = SSLContext.getInstance(RANGER_SSL_CONTEXT_ALGO_TYPE);
	
				sslContext.init(kmList, tmList, new SecureRandom());
				
				return sslContext;
			}
		} catch (NoSuchAlgorithmException e) {
			LOG.error("SSL algorithm is available in the environment", e);
		} catch (KeyManagementException e) {
			LOG.error("Unable to initialize the SSLContext", e);
		}
		
		return null;
	}

	private char[] getCredential(String url, String alias) {
		return RangerCredentialProvider.getInstance().getCredentialString(url, alias);
	}

	private InputStream getFileInputStream(String fileName) throws IOException {
		InputStream in = null;

		if (!StringUtil.isEmpty(fileName)) {
			File f = new File(fileName);

			if (f.exists()) {
				in = new FileInputStream(f);
			} else {
				ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
				if (contextClassLoader != null) {
					in = contextClassLoader.getResourceAsStream(fileName);
				}
				if (in == null) {
					ClassLoader classLoader = RangerSslHelper.class.getClassLoader();
					if (classLoader != null) {
						in = classLoader.getResourceAsStream(fileName);
					}
				}
				if (in == null) {
					in = ClassLoader.getSystemResourceAsStream(fileName);
				}
			}
		}

		return in;
	}

	private void close(InputStream str, String filename) {
		if (str != null) {
			try {
				str.close();
			} catch (IOException excp) {
				LOG.error("Error while closing file: [" + filename + "]", excp);
			}
		}
	}
}
