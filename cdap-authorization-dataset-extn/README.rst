===========================================
CDAP Authorization Extension using Datasets
===========================================

Overview
========

This project contains a CDAP authorization extension using a custom dataset (``ACLDataset``) to store authorization
policies. It implements the CDAP
`Authorizer <https://github.com/caskdata/cdap/blob/develop/cdap-security/src/main/java/co/cask/cdap/security/authorization/Authorizer.java>`_
interface to achieve this integration. The ACLDataset is created in the ``cdap_system`` HBase namespace.

Building
========

To build the CDAP Authorization Dataset Extension and run tests, execute the following command from the
``cdap-authorization-dataset-extn`` root directory::

  $ mvn clean package


To skip tests, execute::

   $ mvn clean package -DskipTests


Deploying
=========

To deploy this authorization extension:

- Install the ``cdap-authorization-dataset-extn/target/cdap-authorization-dataset-extension-*.jar`` at a
known location on your CDAP Master host.
- Set these properties in the ``cdap-site.xml`` that CDAP Master uses:

.. list-table::
   :widths: 20 80
   :header-rows: 1

   * - Parameter
     - Value
   * - ``security.authorization.extension.jar.path``
     - Absolute path of the ``cdap-authorization-dataset-extension-*.jar`` on the local file system of the CDAP Master.
   * - ``security.authorization.extension.config.cdap.superusers``
     - Comma-separated list of super users. Super users are authorized to perform all operations on all entities.

- Restart CDAP Master.

Share and Discuss!
==================

Have a question? Discuss at the `CDAP User Mailing List <https://groups.google.com/forum/#!forum/cdap-user>`__.

License
=======

Copyright © 2016 Cask Data, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
