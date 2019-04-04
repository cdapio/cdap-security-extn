/*
 * Copyright © 2015-2019 Cask Data, Inc.
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

package io.cdap.cdap.security.authorization;

import io.cdap.cdap.api.Admin;
import io.cdap.cdap.api.Transactional;
import io.cdap.cdap.api.TxRunnable;
import io.cdap.cdap.api.dataset.module.DatasetDefinitionRegistry;
import io.cdap.cdap.api.dataset.module.DatasetModule;
import io.cdap.cdap.api.metrics.MetricsCollectionService;
import io.cdap.cdap.api.security.store.SecureStore;
import io.cdap.cdap.api.security.store.SecureStoreManager;
import io.cdap.cdap.common.guice.ConfigModule;
import io.cdap.cdap.common.metrics.NoOpMetricsCollectionService;
import io.cdap.cdap.data.dataset.SystemDatasetInstantiator;
import io.cdap.cdap.data2.dataset2.DatasetDefinitionRegistryFactory;
import io.cdap.cdap.data2.dataset2.DatasetFramework;
import io.cdap.cdap.data2.dataset2.DefaultDatasetDefinitionRegistry;
import io.cdap.cdap.data2.dataset2.DynamicDatasetCache;
import io.cdap.cdap.data2.dataset2.InMemoryDatasetFramework;
import io.cdap.cdap.data2.dataset2.SingleThreadDatasetCache;
import io.cdap.cdap.data2.dataset2.module.lib.inmemory.InMemoryTableModule;
import io.cdap.cdap.internal.app.runtime.DefaultAdmin;
import io.cdap.cdap.proto.id.NamespaceId;
import io.cdap.cdap.security.auth.context.AuthenticationContextModules;
import io.cdap.cdap.security.spi.authentication.AuthenticationContext;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;
import io.cdap.cdap.security.spi.authorization.Authorizer;
import io.cdap.cdap.security.spi.authorization.AuthorizerTest;
import io.cdap.cdap.security.store.DummySecureStore;
import com.google.common.collect.ImmutableMap;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Scopes;
import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.google.inject.multibindings.MapBinder;
import com.google.inject.name.Names;
import org.apache.tephra.TransactionContext;
import org.apache.tephra.TransactionFailureException;
import org.apache.tephra.TransactionManager;
import org.apache.tephra.TransactionSystemClient;
import org.apache.tephra.runtime.TransactionInMemoryModule;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Properties;
/**
 * Tests for {@link DatasetBasedAuthorizer}.
 */
public class DatasetBasedAuthorizerTest extends AuthorizerTest {

  private static final DatasetBasedAuthorizer datasetAuthorizer = new DatasetBasedAuthorizer();
  private static TransactionManager txManager;

  @BeforeClass
  public static void setUpClass() throws Exception {
    Injector injector = Guice.createInjector(
      new TransactionInMemoryModule(),
      new ConfigModule(),
      new AuthenticationContextModules().getMasterModule(),
      new AbstractModule() {
        @Override
        protected void configure() {
          install(new FactoryModuleBuilder()
                    .implement(DatasetDefinitionRegistry.class, DefaultDatasetDefinitionRegistry.class)
                    .build(DatasetDefinitionRegistryFactory.class));

          MapBinder<String, DatasetModule> mapBinder = MapBinder.newMapBinder(
            binder(), String.class, DatasetModule.class, Names.named("defaultDatasetModules"));
          mapBinder.addBinding("orderedTable-memory").toInstance(new InMemoryTableModule());

          bind(DatasetFramework.class).to(InMemoryDatasetFramework.class).in(Scopes.SINGLETON);
          bind(MetricsCollectionService.class).to(NoOpMetricsCollectionService.class);

          DummySecureStore dummySecureStore = new DummySecureStore();
          bind(SecureStore.class).toInstance(dummySecureStore);
          bind(SecureStoreManager.class).toInstance(dummySecureStore);
        }
      }
    );

    txManager = injector.getInstance(TransactionManager.class);
    txManager.startAndWait();

    DatasetFramework dsFramework = injector.getInstance(DatasetFramework.class);
    SystemDatasetInstantiator instantiator = new SystemDatasetInstantiator(dsFramework, null, null);
    TransactionSystemClient txClient = injector.getInstance(TransactionSystemClient.class);
    final DynamicDatasetCache dsCache = new SingleThreadDatasetCache(instantiator, txClient, NamespaceId.DEFAULT,
                                                                     ImmutableMap.<String, String>of(), null, null);
    Admin admin = new DefaultAdmin(dsFramework, NamespaceId.DEFAULT, injector.getInstance(SecureStoreManager.class));
    Transactional txnl = new Transactional() {
      @Override
      public void execute(int timeoutInSeconds, TxRunnable runnable) throws TransactionFailureException {
        TransactionContext transactionContext = dsCache.get();
        transactionContext.start();
        try {
          runnable.run(dsCache);
        } catch (TransactionFailureException e) {
          transactionContext.abort(e);
        } catch (Throwable t) {
          transactionContext.abort(new TransactionFailureException("Exception raised from TxRunnable.run()", t));
        }
        transactionContext.finish();
      }

      @Override
      public void execute(TxRunnable runnable) throws TransactionFailureException {
        execute(15, runnable);
      }

    };
    AuthorizationContext authContext = new DefaultAuthorizationContext(
      new Properties(), dsCache, admin, txnl, injector.getInstance(AuthenticationContext.class),
      injector.getInstance(SecureStore.class)
    );
    datasetAuthorizer.initialize(authContext);
  }

  @AfterClass
  public static void tearDownClass() throws Exception {
    datasetAuthorizer.destroy();
    txManager.stopAndWait();
  }

  @Override
  protected Authorizer get() {
    return datasetAuthorizer;
  }

  @Override
  @Test(expected = UnsupportedOperationException.class)
  public void testRBAC() throws Exception {
    // DatasetBasedAuthorizer currently does not support role based access control
    super.testRBAC();
  }
}
