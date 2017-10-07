================================================
CDAP Authorization Extension using Apache Sentry
================================================

Introduction
============

Apache Ranger is centralized security framework used to manage
authorization privileges. `Read more <http://ranger.apache.org/>`__

Architecture
============

CDAP Ranger extension consists of three major components:

1. CDAP Ranger Loookup: Enables Ranger to lookup CDAP entities.
2. CDAP Ranger Binding: Enables CDAP to use privileges in Ranger for
   enforcement.
3. CDAP Ranger Service Definition: Defines CDAP as a service and it's
   resources in Ranger.

.. image:: _images/architecture.png
  :align: center

Installation
============

Before enabling CDAP Authorization please read the following
`documentation <https://docs.cask.co/cdap/current/en/admin-manual/security/authorization.html#admin-authorization>`__.

Installing CDAP Lookup in Ranger
--------------------------------

1. Create a new folder called ``cdap`` under your Ranger plugins
   directory. Typically on Ambari clusters it is:
   */usr/hdp/current/ranger-admin/ews/webapp/WEB-INF/classes/ranger-plugins*

    mkdir cdap

    cd cdap

2. Move the CDAP Ranger Lookup jar to the cdap plugin directory created
   above.

    mv
    path-to-jar/cdap-ranger-lookup-[version]-jar-with-dependencies.jar
    ./

3. Change permission to the cdap plugin directory (if required)

    chown -R ranger:ranger cdap/

4. Restart Ranger service

Adding CDAP as a service in Ranger
----------------------------------

1. You can use the
   *`ranger-servicedef-cdap.json <https://github.com/caskdata/cdap-security-extn/blob/develop/cdap-ranger/cdap-ranger-lookup/src/main/resources/ranger-servicedef-cdap.json>`__*
   to add CDAP as a service in Ranger

    curl -u ranger-admin-user:ranger-admin-password -X POST -H "Accept:
    application/json" -H "Content-Type: application/json" -d
    @ranger-servicedef-cdap.json
    http://rangerhost:rangerport/service/plugins/definitions

2. Now go to the Ranger Admin UI and click on the + button for CDAP
   service.

.. image:: _images/ranger_install1.png
  :align: center

3. Fill in the details of your CDAP instance.

+---------------------------------+-----------------------------------------------+--------------------------+
| Configuration                   | Definition                                    | Example                  |
+=================================+===============================================+==========================+
| Service Name                    | Name of this service                          | cdapdev                  |
+---------------------------------+-----------------------------------------------+--------------------------+
| Username                        | Username to use to connect to cdap instance   | username                 |
+---------------------------------+-----------------------------------------------+--------------------------+
| Password                        | Password for the above user                   | password                 |
+---------------------------------+-----------------------------------------------+--------------------------+
| Instance URL                    | CDAP instance URL                             | mycdaphost:router-port   |
+---------------------------------+-----------------------------------------------+--------------------------+
| **Add New Configuration**       |                                               |                          |
+---------------------------------+-----------------------------------------------+--------------------------+
| policy.download.auth.users      | User allowed to download policies             | cdap                     |
+---------------------------------+-----------------------------------------------+--------------------------+
| policy.grantrevoke.auth.users   | User allowed to grant/revoke                  | cdap                     |
+---------------------------------+-----------------------------------------------+--------------------------+

*Note: CDAP username and password is only needed if you want lookup of
(auto completion of entity names) CDAP entities in Ranger Admin UI. This
user must have authorization for the entities to be able to look it up.
Please see documentation below on how to add these privileges. Although,
it is not necessary for this user to have authorization on all entities.
In this case you will not be able to use auto completion of entity names
in Ranger Admin UI and will have to type complete entity names.*

.. image:: _images/ranger_install2.png
  :align: center

4. Click on **Test Connection** button to test that Ranger can
   successfully establish connection with CDAP.

.. image:: _images/ranger_install3.png
  :align: center

5. Now click on **Add** button, this will add the CDAP service in
   Ranger.

6. Once the CDAP service is added in Ranger you will see that Ranger
   creates some default wildcard policies without any users/groups
   assigned to it.

.. image:: _images/ranger_install4.png
  :align: center

*Optional: As mentioned earlier if you want Ranger to be able to lookup
CDAP entities you will need to give the connecting user specified during
service definition ANY (READ, WRITE, EXECUTE or ADMIN) privilege on all
entities. You can just go ahead and add that user with some permission
to the above existing policies. Note: This is an optional step. You can
still use CDAP Ranger Extension without granting the above connecting
user ANY privilege on all the resource although you will not be able to
use lookup feature in Ranger and will have to manually type complete
entity names.*

.. image:: _images/ranger_install5.png
  :align: center

Installing CDAP Authorization Binding for Enforcement
-----------------------------------------------------

1. Put the Ranger CDAP configuration xml files under some path which is
   accessible to ``cdap`` user. For example:

    mkdir /usr/local/ranger-cdap-conf

2. Put the following `three
   files <https://github.com/caskdata/cdap-security-extn/tree/38a974e56912ffc4e06aecaa3aaf9bbc7bc53682/cdap-ranger/cdap-ranger-binding/conf>`__
   in this directory

-  ranger-cdap-audit.xml
-  ranger-cdap-security.xml
-  ranger-policymgr-ssl.xml

You can download a CDAP specific sample here. You might need to modify
these configuration files according to your environment but the default
will work fine in most cases.

3. Edit the ``ranger-cdap-security.xml`` file

+----------------------------+--------------------------------------+-----------+
| Configuration              | Definition                           | Example   |
+============================+======================================+===========+
| ranger.plugin.cdap.policy. | Name of this service                 | http://ra |
| rest.url                   |                                      | ngerhost: |
|                            |                                      | port      |
+----------------------------+--------------------------------------+-----------+
| ranger.plugin.cdap.service | Service name given in Ranger while   | cdapdev   |
| .name                      | adding CDAP                          |           |
+----------------------------+--------------------------------------+-----------+

4. Give ``cdap`` user permission on the above created directory and
   configuration files

    chown -R cdap:cdap /usr/local/ranger-cdap-conf/

5. Move the CDAP Ranger Binding jar to correct directory (if needed) and
   give cdap permissions on it

    mv /cdap-ranger-binding-0.1.0.jar /opt/cdap/master/ext/security/

    chown cdap:cdap cdap-ranger-binding-0.1.0.jar

6. Edit the CDAP configuration in Ambari Admin UI and add the following
   in the custom cdap-site.xml section

::

    security.authorization.enabled=true
    security.authorization.extension.extra.classpath=/usr/local/ranger-cdap-conf
    security.authorization.extension.jar.path=/opt/cdap/master/ext/security/cdap-ranger-binding-0.1.0.jar

7. Save and Restart CDAP.

Policy Management
=================

Policies on mid-level entities
------------------------------

CDAP Policies can be managed in Ranger just like other service policies.
Please read the `Ranger
documentation <https://cwiki.apache.org/confluence/display/RANGER/Apache+Ranger+0.5+-+User+Guide>`__
on Policy management to learn more.

CDAP Ranger Plugin allows to grant policies on mid-level entities in
CDAP entity hierarchy by specifying ``*`` for lower level and marking
them as ``exclude``. For example the below screenshot shows the policy
on ``namespace:default``. Notice that the value for ``application`` and
``program`` are ``*`` and they are marked as ``exclude``.

.. image:: _images/policy_management.png
  :align: center

Wildcard Policies
-----------------

CDAP Ranger plugin allows to `grant wildcard policies <https://docs.cask
.co/cdap/current/en/admin-manual/security/authorization.html#wildcard-privileges>`__ on entities.
The supported wildcards are ``*`` and ``?``. ``*`` wildcard in Ranger matches 0 or more characters. CDAP does not
expect wildcard ``*`` to match 0 characters (absence of value) so a ``*`` should always be prefixed with ``?``. For
example to grant a user privilege on all ``programs`` the wildcard value should be as shown below.

.. image:: _images/policy_management_wildcard.png
:align: center

Building Ranger Extension
=========================

CDAP Ranger extension can be built from source code by running the
following command:

    mvn clean package

To build without running unit tests

    mvn clean package -DskipTests

Optionally, you can download pre-built extension jars from `maven
central <https://search.maven.org/#search%7Cga%7C1%7Ccdap%20ranger>`__.

Share and Discuss!
==================
Have a question? Discuss at the `CDAP User Mailing List <https://groups.google.com/forum/#!forum/cdap-user>`__.

License
=======

Copyright © 2017 Cask Data, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0