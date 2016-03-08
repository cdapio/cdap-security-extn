=========================================
CDAP Security Extension for Apache Sentry
=========================================

Overview
========

This project integrates CDAP with Apache Sentry to delegate authorization (both ACL Management and Enforcement) to
Apache Sentry. It implements the CDAP
`Authorizer <https://github.com/caskdata/cdap/blob/develop/cdap-security/src/main/java/co/cask/cdap/security/authorization/Authorizer.java>`_
interface to achieve this integration.

Code Organization
=================

This code is organized into three submodules:

CDAP Sentry Model
-----------------

Defines the CDAP Data Model in Sentry. Used in both the Sentry Service and the Sentry Client (which runs inside the
CDAP Master).

CDAP Sentry Policy Engine
-------------------------

Defines authorization policies for CDAP entities in Sentry. It depends on the CDAP Sentry Model. It runs inside the
Sentry Service and is not required in the Sentry Client.

CDAP Sentry Binding
-------------------

Defines binding between the CDAP entities and the CDAP Data Model in the Sentry Service. Runs inside the Sentry Client
which runs inside the CDAP Master.

Building
========

Prerequisites
-------------
Since Apache Sentry releases are source-only, this project assumes that Sentry has been pre-built and installed in the
local maven repo. To do this, in the Apache Sentry source root directory please run::

  mvn clean install -DskipTests


``cdap-sentry`` is a Maven project with two basic profiles:

``default``
-----------

Builds a basic ``cdap-sentry`` jar with no dependencies. To build this profile, run::

  mvn clean package


``with-dependencies``
---------------------

Builds two jars - A jar with no dependencies, and a jar with first-level dependencies. This profile is only applicable
to the CDAP Sentry Binding module. The jar with dependencies can be used by CDAP so all the required dependencies are
available to the Sentry Client running in the CDAP Master. To build this profile, run::

  mvn clean package -Pwith-dependencies


Deploying
=========

The server side code only requires CDAP Sentry Policy and the CDAP Sentry Model classes. So, the
``cdap-sentry-policy/target/cdap-sentry-policy-*.jar`` and ``cdap-sentry-model/target/cdap-sentry-model-*.jar``
should be deployed in the ``[SENTRY_HOME_DIR]/lib`` directory on the Sentry Service host.

The client side requires the CDAP Sentry Binding and the CDAP Sentry Model classes as well as their dependencies. So
the ``cdap-sentry-binding/target/cdap-sentry-binding-*.jar``, which is a fat jar containing all the required
dependencies should be deployed in the ``[CDAP_HOME]/lib`` directory on the CDAP Master host.

After deploying the ``cdap-sentry`` jars, please restart the respective services (Apache Sentry Server and CDAP Master).

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
