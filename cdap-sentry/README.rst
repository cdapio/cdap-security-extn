=========================================
CDAP Security Extension for Apache Sentry
=========================================

Overview
========

This project integrates CDAP with Apache Sentry to delegate authorization (both ACL Management and Enforcement) to
Apache Sentry. It implements the CDAP
`Authorizer <https://github.com/caskdata/cdap/blob/develop/cdap-security/src/main/java/co/cask/cdap/security/authorization/Authorizer.java>`_
interface to achieve this integration.

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

Builds two jars - A jar with no dependencies, and a jar with first-level dependencies. To
build this profile, run::

  mvn clean package -Pwith-dependencies


Deploying
=========

The ``cdap-sentry`` code has both Apache Sentry server side and client side (CDAP) code. The server side code only
requires ``cdap-sentry`` classes, so the ``target/cdap-sentry-*.jar`` should be deployed in the
``[SENTRY_HOME_DIR]/lib`` directory. The client side requires the ``cdap-sentry`` classes as well as the first level
dependencies, so the ``target/cdap-sentry-*-with-dependencies.jar`` should be deployed in the ``[CDAP_HOME]/lib``
directory.

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
