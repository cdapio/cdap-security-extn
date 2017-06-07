package org.apache.sentry.core.model.search;

import org.apache.sentry.core.common.BitFieldAction;
import org.apache.sentry.core.common.BitFieldActionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This is a dummy class to just get the Sentry Server to startup in test without including unnecessary dependencies.
 */
public class SearchActionFactory extends BitFieldActionFactory {
  private static final Logger LOG = LoggerFactory.getLogger(SearchActionFactory.class);

  static {
    LOG.info("Using dummy {} in test", SearchActionFactory.class.getName());
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
