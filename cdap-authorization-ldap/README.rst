=======================================
CDAP Authorization Extension using LDAP
=======================================

Overview
========

This project contains a CDAP authorization extension using LDAP for authorization enforcement. It implements the CDAP
`Authorizer <https://github.com/caskdata/cdap/blob/develop/cdap-security/src/main/java/co/cask/cdap/security/authorization/Authorizer.java>`_
interface to achieve this integration.

Building
========

To build the CDAP Authorization LDAP Extension, execute the following command from the
``cdap-authorization-ldap`` root directory::

  mvn clean package


Deploying
=========

To deploy this authorization extension:

- Install the ``cdap-authorization-ldap/target/cdap-authorization-ldap-*.jar`` at a
known location on your CDAP Master host.
- Set the following properties in the ``cdap-site.xml`` that the Master uses:

.. list-table::
   :widths: 20 80
   :header-rows: 1

   * - Parameter
     - Value
   * - ``security.authorization.extension.jar.path``
     - Absolute path of the ``cdap-authorization-ldap-*.jar`` on the local file system of the CDAP Master.
   * - ``security.authorization.extension.config.java.naming.provider.url``
     - The provider URL for the LDAP server to use. It must be in the form of ``ldap://host:port`` or ``ldaps://host:port``
   * - ``security.authorization.extension.config.instanceBaseDn``
     - The base DN for CDAP instance search
   * - ``security.authorization.extension.config.instanceObjectClass``
     - The ObjectClass to search for instance member attribute
   * - ``security.authorization.extension.config.instanceMemberAttribute``
     - The attribute to search for instance membership
   * - ``security.authorization.extension.config.instanceNameAttribute``
     - The attribute that stores the CDAP instance name
   * - ``security.authorization.extension.config.namespaceBaseDn``
     - The base DN for namespace search
   * - ``security.authorization.extension.config.namespaceObjectClass``
     - The ObjectClass to search for namespace member attribute
   * - ``security.authorization.extension.config.namespaceMemberAttribute``
     - The attribute to search for namespace membership
   * - ``security.authorization.extension.config.namespaceNameAttribute``
     - The attribute that stores the CDAP namespace name
   * - ``security.authorization.extension.config.userBaseDn``
     - The base DN for user id search
   * - ``security.authorization.extension.config.userRdnAttribute``
     - The attribute that stores the user RDN

- You can optionally provide the following properties in the ``cdap-site.xml``:

.. list-table::
   :widths: 20 80
   :header-rows: 1

   * - Parameter
     - Value
   * - ``security.authorization.extension.sslVerifyCertificate``
     - If SSL is used, set to ``true`` to have SSL certificate verification or ``false`` to disable it. The default value is ``true``.
   * - ``security.authorization.extension.java.naming.security.principal``
     - Specifying the identity of the principal for LDAP authentication
   * - ``security.authorization.extension.credentialsKeyName``
     - Specifying the key in the CDAP secure store to fetch the credentials to be used for LDAP authentication
   * - ``security.authorization.extension.searchRecursive``
     - If set to ``true``, entire subtree rooted at ``namespaceBaseDn`` will be searched. By default, only one level of subtree will be searched.

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
