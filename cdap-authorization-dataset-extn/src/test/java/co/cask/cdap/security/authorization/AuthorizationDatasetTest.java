/*
 * Copyright © 2015-2016 Cask Data, Inc.
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

package co.cask.cdap.security.authorization;

import co.cask.cdap.api.dataset.DatasetProperties;
import co.cask.cdap.api.dataset.table.Table;
import co.cask.cdap.data2.dataset2.DatasetFrameworkTestUtil;
import co.cask.cdap.proto.id.DatasetId;
import co.cask.cdap.proto.id.Ids;
import co.cask.cdap.proto.id.NamespaceId;
import co.cask.cdap.proto.security.Action;
import co.cask.cdap.proto.security.Principal;
import co.cask.cdap.proto.security.Privilege;
import com.google.common.collect.ImmutableSet;
import org.apache.tephra.TransactionExecutor;
import org.apache.tephra.TransactionFailureException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

/**
 * Tests for {@link AuthorizationDataset}.
 */
public class AuthorizationDatasetTest {

  @ClassRule
  public static DatasetFrameworkTestUtil dsFrameworkUtil = new DatasetFrameworkTestUtil();

  private static final DatasetId tabInstance = new DatasetId("myspace", "tab");
  private static AuthorizationDataset table;

  @BeforeClass
  public static void beforeClass() throws Exception {
    dsFrameworkUtil.createInstance("table", tabInstance, DatasetProperties.EMPTY);
    table = new AuthorizationDataset((Table) dsFrameworkUtil.getInstance(tabInstance));
  }

  @AfterClass
  public static void afterClass() throws Exception {
    dsFrameworkUtil.deleteInstance(tabInstance);
  }

  @Test
  public void testSearchAddRemove() throws InterruptedException, TransactionFailureException {
    final NamespaceId namespace = Ids.namespace("foo");
    final Principal user = new Principal("alice", Principal.PrincipalType.USER);

    TransactionExecutor txnl = dsFrameworkUtil.newTransactionExecutor(table);

    txnl.execute(new TransactionExecutor.Subroutine() {
      @Override
      public void apply() throws Exception {
        Assert.assertEquals(ImmutableSet.of(), table.search(namespace, user));
      }
    });
    // single add and single remove
    txnl.execute(new TransactionExecutor.Subroutine() {
      @Override
      public void apply() throws Exception {
        table.add(namespace, user, Action.READ);
        Assert.assertEquals(ImmutableSet.of(Action.READ), table.search(namespace, user));
        Assert.assertEquals(ImmutableSet.of(new Privilege(namespace, Action.READ)), table.listPrivileges(user));
        table.remove(namespace, user, Action.READ);
        Assert.assertEquals(ImmutableSet.of(), table.search(namespace, user));
      }
    });

    // two adds and batch remove
    txnl.execute(new TransactionExecutor.Subroutine() {
      @Override
      public void apply() throws Exception {
        table.add(namespace, user, Action.READ);
        table.add(namespace, user, Action.WRITE);
        Assert.assertEquals(ImmutableSet.of(Action.READ, Action.WRITE), table.search(namespace, user));
        table.remove(namespace, user);
        Assert.assertEquals(ImmutableSet.of(), table.search(namespace, user));
      }
    });

    // two adds and batch remove
    txnl.execute(new TransactionExecutor.Subroutine() {
      @Override
      public void apply() throws Exception {
        table.add(namespace, user, Action.READ);
        table.add(namespace, user, Action.WRITE);
        Assert.assertEquals(ImmutableSet.of(Action.READ, Action.WRITE), table.search(namespace, user));
        table.remove(namespace);
        Assert.assertEquals(ImmutableSet.of(), table.search(namespace, user));
      }
    });
  }

}
