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

import io.cdap.cdap.api.Predicate;
import io.cdap.cdap.api.TxRunnable;
import io.cdap.cdap.api.data.DatasetContext;
import io.cdap.cdap.api.dataset.DatasetManagementException;
import io.cdap.cdap.api.dataset.DatasetProperties;
import io.cdap.cdap.api.dataset.InstanceConflictException;
import io.cdap.cdap.api.dataset.table.Table;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.proto.security.Privilege;
import io.cdap.cdap.proto.security.Role;
import io.cdap.cdap.security.spi.authorization.AbstractAuthorizer;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;
import io.cdap.cdap.security.spi.authorization.Authorizer;
import io.cdap.cdap.security.spi.authorization.RoleAlreadyExistsException;
import io.cdap.cdap.security.spi.authorization.RoleNotFoundException;
import io.cdap.cdap.security.spi.authorization.UnauthorizedException;
import com.google.common.base.Splitter;
import com.google.common.base.Supplier;
import com.google.common.base.Throwables;
import org.apache.tephra.TransactionFailureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * {@link Authorizer} that uses a dataset to manage ACLs.
 */
public class DatasetBasedAuthorizer extends AbstractAuthorizer {
  private static final Logger LOG = LoggerFactory.getLogger(DatasetBasedAuthorizer.class);
  private final Set<Principal> superUsers = new HashSet<>();
  private AuthorizationContext context;
  private Supplier<AuthorizationDataset> dsSupplier;

  @Override
  public void initialize(final AuthorizationContext context) throws Exception {
    this.context = context;
    this.dsSupplier = new Supplier<AuthorizationDataset>() {
      @Override
      public AuthorizationDataset get() {
        try {
          context.createDataset(AuthorizationDataset.TABLE_NAME, "table", DatasetProperties.EMPTY);
        } catch (InstanceConflictException e) {
          LOG.info("Dataset {} already exists. Not creating again.", AuthorizationDataset.TABLE_NAME);
        } catch (DatasetManagementException e) {
          throw Throwables.propagate(e);
        }
        Table table = context.getDataset(AuthorizationDataset.TABLE_NAME);
        return new AuthorizationDataset(table);
      }
    };
    Properties properties = context.getExtensionProperties();
    if (!properties.containsKey("superusers")) {
      LOG.warn("No superusers configured. The system may become unusable when authorization is enabled but " +
                 "superusers are not configured. Please set the property " +
                 "security.authorization.extension.config.superusers to a comma-separated list of superusers in " +
                 "cdap-site.xml and restart CDAP.");
      return;
    }
    for (String superuser : Splitter.on(",").trimResults().omitEmptyStrings()
      .split(properties.getProperty("superusers"))) {
      this.superUsers.add(new Principal(superuser, Principal.PrincipalType.USER));
    }
  }

  @Override
  public void enforce(final EntityId entity, final Principal principal, final Set<Action> actions) throws Exception {
    // no enforcement for superusers
    if (superUsers.contains(principal)) {
      return;
    }
    final AtomicReference<Boolean> result = new AtomicReference<>(false);
    context.execute(new TxRunnable() {
      @Override
      public void run(DatasetContext context) throws Exception {
        AuthorizationDataset dataset = dsSupplier.get();
        for (EntityId current : entity.getHierarchy()) {
          Set<Action> allowedActions = dataset.search(current, principal);
          if (allowedActions.containsAll(actions)) {
            result.set(true);
            return;
          }
        }
      }
    });
    if (!result.get()) {
      throw new UnauthorizedException(principal, actions, entity);
    }
  }

  @Override
  public Predicate<EntityId> createFilter(Principal principal) throws Exception {
    // no filtering for superusers
    if (superUsers.contains(principal)) {
      return ALLOW_ALL;
    }
    return super.createFilter(principal);
  }

  @Override
  public void grant(final EntityId entity, final Principal principal,
                    final Set<Action> actions) throws TransactionFailureException {
    context.execute(new TxRunnable() {
      @Override
      public void run(DatasetContext context) throws Exception {
        AuthorizationDataset dataset = dsSupplier.get();
        for (Action action : actions) {
          dataset.add(entity, principal, action);
        }
      }
    });
  }

  @Override
  public void revoke(final EntityId entity, final Principal principal,
                     final Set<Action> actions) throws TransactionFailureException {
    context.execute(new TxRunnable() {
      @Override
      public void run(DatasetContext context) throws Exception {
        AuthorizationDataset dataset = dsSupplier.get();
        for (Action action : actions) {
          dataset.remove(entity, principal, action);
        }
      }
    });
  }

  @Override
  public void revoke(final EntityId entity) throws TransactionFailureException {
    context.execute(new TxRunnable() {
      @Override
      public void run(DatasetContext context) throws Exception {
        AuthorizationDataset dataset = dsSupplier.get();
        dataset.remove(entity);
      }
    });
  }

  @Override
  public Set<Privilege> listPrivileges(final Principal principal) throws TransactionFailureException {
    final AtomicReference<Set<Privilege>> result = new AtomicReference<>();
    context.execute(new TxRunnable() {
      @Override
      public void run(DatasetContext context) throws Exception {
        AuthorizationDataset dataset = dsSupplier.get();
        result.set(dataset.listPrivileges(principal));
      }
    });
    return result.get();
  }

  @Override
  public void createRole(Role role) throws RoleAlreadyExistsException {
    throw new UnsupportedOperationException("Role based operation is not supported.");
  }

  @Override
  public void dropRole(Role role) throws RoleNotFoundException {
    throw new UnsupportedOperationException("Role based operation is not supported.");
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws RoleNotFoundException {
    throw new UnsupportedOperationException("Role based operation is not supported.");
  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws RoleNotFoundException {
    throw new UnsupportedOperationException("Role based operation is not supported.");
  }

  @Override
  public Set<Role> listRoles(Principal principal) {
    throw new UnsupportedOperationException("Role based operation is not supported.");
  }

  @Override
  public Set<Role> listAllRoles() {
    throw new UnsupportedOperationException("Role based operation is not supported.");
  }
}
