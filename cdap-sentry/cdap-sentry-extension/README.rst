================================================
CDAP Authorization Extension using Apache Sentry
================================================

Overview
========

This project integrates CDAP with Apache Sentry to delegate authorization (both ACL
Management and Enforcement) to Apache Sentry. It implements the CDAP `Authorizer 
<https://github.com/caskdata/cdap/blob/develop/cdap-security/src/main/java/co/cask/cdap/security/authorization/Authorizer.java>`_
interface to achieve this integration. This project is implemented as a CDAP Authorizer
extension.

Code Organization
=================
This code is organized into three submodules:

CDAP Sentry Model
-----------------
Defines the CDAP Data Model in Sentry. Used in both the Sentry Service and the Sentry
Client (which runs inside the CDAP Master).

CDAP Sentry Policy Engine
-------------------------
Defines authorization policies for CDAP entities in Sentry. It depends on the CDAP Sentry
Model. It runs inside the Sentry Service and is not required in the Sentry Client.

CDAP Sentry Binding
-------------------
Defines binding between the CDAP entities and the CDAP Data Model in the Sentry Service.
Runs inside the Sentry Client which runs inside the CDAP Master.

Building
========

Prerequisites
-------------
Since Apache Sentry releases are source-only, this project assumes that Apache Sentry
1.7.0 has been pre-built and installed in the local Maven repo. To do this, in the Apache
Sentry source root directory, run::

  $ git fetch origin
  $ git checkout branch-1.7.0
  $ mvn clean install -DskipTests


To build the CDAP Sentry Extension and run tests, execute this command from the ``cdap-sentry``
root directory::

  $ mvn clean package


To skip tests, execute::

   $ mvn clean package -DskipTests


Deploying
=========

Sentry Server-side Deployment
-----------------------------
The server-side code only requires the CDAP Sentry Policy and the CDAP Sentry Model
classes. As a result, these JARs should be deployed on the host running the Sentry Service:

- ``cdap-sentry-extension/cdap-sentry-policy/target/cdap-sentry-policy-*.jar``
- ``cdap-sentry-extension/cdap-sentry-model/target/cdap-sentry-model-*.jar``

There are two options for deploying these jars:

- Copy them to the ``[SENTRY_HOME_DIR]/lib`` directory; or
- Set ``HADOOP_CLASSPATH`` to the location containing these jar files. 

  On a `Cloudera Manager <https://www.cloudera.com/products/cloudera-manager.html>`__
  managed cluster, the ``HADOOP_CLASSPATH`` can be set under the *Sentry Service
  Environment Advanced Configuration Snippet (Safety Valve)* configuration setting for the
  Sentry Service.

Additionally, these configurations should be specified in the ``sentry-site.xml`` used by
the Sentry Service:

- The ``cdap`` user should be added to ``sentry.service.allow.connect``
- The ``cdap`` user should be added to ``sentry.service.admin.group``
- An additional setting, ``sentry.cdap.action.factory``, should be set to
  ``co.cask.cdap.security.authorization.sentry.model.ActionFactory``; this setting can be
  added as a *Sentry Service Advanced Configuration Snippet (Safety Valve) for
  sentry-site.xml*

After updating these JARs and settings, restart the Sentry Service.

CDAP Master-side Deployment
---------------------------
The CDAP Master, which is also a client for the Sentry service, requires the CDAP Sentry
Binding classes as well as its dependencies. To deploy the ``cdap-sentry`` authorization
extension:

- Install the ``cdap-sentry-extension/cdap-sentry-binding/target/cdap-sentry-binding-*.jar`` 
  at a known location on your CDAP Master host
- Set these properties in the ``cdap-site.xml`` that the CDAP Master uses:

  .. list-table::
     :widths: 20 70 10
     :header-rows: 1

     * - Parameter
       - Description
       - Default Value
     * - ``security.authorization.enabled``
       - Set it to ``true`` to turn on CDAP Authorization
       - *false*
     * - ``security.authorization.extension.jar.path``
       - The absolute path, including the filename, of the ``cdap-sentry-binding-*.jar``
         file on the local file system of the CDAP Master
       - *none*
     * - ``security.authorization.extension.config.sentry.site.url``
       - The absolute path of the client-side ``sentry-site.xml`` on the local file system
         of the CDAP Master. Note that if Apache Sentry is managed via Cloudera Manager, you can
         add a Sentry Gateway role to the CDAP Master host, and the file will be available
         at ``/etc/sentry/conf/sentry-site.xml`` on the CDAP Master host. Alternatively, you
         can download this file from the *Actions -> Download Client Configuration* drop
         down link in the "Configuration" tab of the Sentry Service, and copy it to a
         location of your choice on the CDAP Master host.
       - *none*
     * - ``security.authorization.extension.config.sentry.admin.group``
       - A UNIX group configured as an admin group in the Sentry Service (identified by
         ``sentry.service.admin.group`` in the ``sentry-site.xml`` used by the Sentry
         Service). This group is used when granting all privileges to a user when they
         have successfully created an entity, as well as for revoking privileges when an
         entity is deleted. It is required to list privileges and roles in Sentry for
         enforcing authorization on CDAP entities. It is recommended that the ``cdap`` user
         (which runs the CDAP Master) be added to the ``sentry.service.admin.group``
         configuration, but any other user is also acceptable.
       - ``cdap``
     * - ``instance.name``
       - String used to identify the CDAP Instance
       - ``cdap``

After installing the JAR and setting these properties, restart CDAP Master.

Share and Discuss!
==================
Have a question? Discuss at the `CDAP User Mailing List <https://groups.google.com/forum/#!forum/cdap-user>`__.

License
=======

Copyright © 2016-2017 Cask Data, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
