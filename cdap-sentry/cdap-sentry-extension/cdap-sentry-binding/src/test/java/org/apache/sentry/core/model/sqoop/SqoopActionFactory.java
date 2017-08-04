/*
 * Copyright © 2017 Cask Data, Inc.
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

package org.apache.sentry.core.model.sqoop;

import org.apache.sentry.core.common.BitFieldAction;
import org.apache.sentry.core.common.BitFieldActionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This is a dummy class to just get the Sentry Server to startup in test without including unnecessary dependencies.
 */
public class SqoopActionFactory extends BitFieldActionFactory {
  private static final Logger LOG = LoggerFactory.getLogger(SqoopActionFactory.class);

  static {
    LOG.info("Using dummy {} in test", SqoopActionFactory.class.getName());
  }

  @Override
  public List<? extends BitFieldAction> getActionsByCode(int i) {
    return null;
  }

  @Override
  public BitFieldAction getActionByName(String s) {
    return null;
  }
}
