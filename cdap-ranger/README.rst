CDAP Authorization Extension using Apache Ranger 
------------------------------------------------

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

A Case Study
============

Consider a common use case for secure environments, especially data lakes:

- There are different "categories" of data. For example, click events, financial data, operational metrics, etc.
- Users typically have access to some but not all data. Therefore, data that is commonly accessed together,
  is grouped into a category, for example, ``finance``.
- All data in a category is owned by a headless service account, and access to the data is given through group
  permissions or similar, more coarse, privilege roles.
- Nobody ever logs on as the headless service account.
- The applications and pipelines that create and process the data are managed by Operators, that is,
  real persons who log on to the UI with their own user name and password.
- Consumers of the data are data scientists (real persons) or downstream applications (headless).

In CDAP, this is implemented as a namespace that impersonates the headless service account. Let's study
such a use case at the hand of an example. Suppose that:

- There are two data categories: finance and clicks, represented as namespaces of the name names.
- Each namespace is owned and impersonated by a headless user: ``svcfinance`` and ``svcclicks``,
  respectively.
- These headless users have a keytab associated with them, which will be used to impersonate the
  corresponding Kerberos principals.
- All data in each namespace is owned by the headless user, and all data pipelines in that namespace
  are run as the corresponding Kerberos principal.
- Alice and Bob are both operators and they deploy, manage and monitor the pipelines in all namespaces.

In a cluster with Ranger authorization, what are the Ranger policies required to enable this scenario?
Let’s go through the steps:

1. To begin with, we need two Unix users with Kerberos principals and keytab files that will 
allow impersonating them:

.. image:: _images/ranger-case-study-keytabs.png
  :align: center

Note that these key tabs must be readable for the cdap system account.

2. To create the ``clicks`` namespace, Alice logs into the CDAP UI. Initially, she cannot access any
   namespaces:

.. image:: _images/ranger-case-study-no-access.png
  :align: center

To allow her the creation of these two namespaces with impersonation, we need to give her privileges
on the principals and the namespaces in Ranger:

.. image:: _images/ranger-case-study-policy-principals.png
  :align: center

Here, we give Alice ``ADMIN`` right on any principal starting with ``svc``.
If you need more control, you can also give an explicit list of principals, as we
do here for the namespaces:

.. image:: _images/ranger-case-study-policy-namespace.png
  :align: center

Due to a limitation in Ranger, it is not possible to assign policies for “intermediate”
entities in the entity hierarchy. Because of that, we need to use the work-around above:
Specify ``*`` for both the application and the program, and select “exclude” for both of them.
This is the way to define a policy for a namespace.

3. Now Alice can create the two namespaces, for example, ``clicks``:

.. image:: _images/ranger-case-study-create-ns.png
  :align: center

.. image:: _images/ranger-case-study-create-ns2.png
  :align: center

.. image:: _images/ranger-case-study-create-ns3.png
  :align: center

.. image:: _images/ranger-case-study-create-ns4.png
  :align: center

4. Now let’s create a pipeline. Without additional policies in Ranger, this will fail:

.. image:: _images/ranger-case-study-deploy-fail1.png
  :align: center

We are required to give Alice ``ADMIN`` privileges on the pipeline applications she deploys.

Note that in CDAP, an application is a group of programs that logically belong together.
A pipeline is an application with the same name as the pipeline. It contains the Data Pipeline
Workflow and the MapReduce or Spark programs that execute the pipeline. For deploying the pipeline,
we need ``ADMIN`` rights on this application. Here, we give these rights for all applications
in the namespace, that is, Alice can deploy any pipeline:

.. image:: _images/ranger-case-study-policy-apps.png
  :align: center

Similar to namespace policies, we need to work around a ranger limitation to assign
policies to an application. Enter ``?*`` for "application" and ``*`` for "program" and
select “exclude” for the program.

Now let’s try to deploy the pipeline again:

.. image:: _images/ranger-case-study-deploy-fail2.png
  :align: center

This still fails because the pipeline is trying to create the datasets for its source and sink,
but we have not given any privileges on datasets yet. Because the pipeline is impersonated as
the service account ``svcclicks``, we must assign these privileges to that user. Strictly speaking,
only ``ADMIN`` is required to create the datasets, but later on, when we run the pipeline, it will
need read and write access, too. Therefore, we just assign all these privileges now:

.. image:: _images/ranger-case-study-policy-datasets.png
  :align: center


With this, pipeline deployment succeeds.

5. Let’s run the pipeline to ingest some data. Starting the pipeline is equivalent to starting
the DataPipelineWorkflow program of the pipeline’s application. This fails with insufficient
privileges. However, the error message does not make this obvious:

.. image:: _images/ranger-case-study-start-fail.png
  :align: center

Because Alice has no privileges at all on the pipeline’s programs, it is also not allowed
to find out about their existence. Therefore, the platform APIs return a “Not Found” error
for this request. This can be confusing at first - however, it is common practice for
secure APIs to behave this way.

Let’s assign the missing privileges to Alice:

.. image:: _images/ranger-case-study-policy-programs.png
  :align: center

Note that only the ``EXECUTE`` privilege is required to start or stop a pipeline run,
and the ``ADMIN`` privilege is needed to schedule the pipeline.

Now Alice can run this pipeline:

.. image:: _images/ranger-case-study-start-success.png
  :align: center

6. We can repeat these steps to assign similar privileges to Bob, or to enable the
``finance`` namespace. Also, we could assign privileges to groups rather than
individuals - that will make our policies easier to manage over time, especially
when new operators enter the team, or existing ones leave: that will simply
require adding or removing a user from the group.

Conclusion
----------

We have created a namespace that is impersonated by a headless service account;
and we have given privileges to a human user to deploy and operate pipelines in
the namespace. To summarize all the privileges we had to assign:

- For the headless service principal:

  - ADMIN, READ and WRITE on the datasets in the namespace, required to create,
    manage, read, and write data;

- For the human operator:

  - ADMIN privilege on the service user’s kerberos principal, required to
    configure a namespace to impersonate that user;
  - ADMIN on the namespace, required to create and operate the namespace;
  - ADMIN on the applications in the namespace, required to create and operate pipelines;
  - EXECUTE and ADMIN on the programs in the namespace. EXECUTE is required to
    run a pipeline and ADMIN is required to schedule runs.

This concludes the case study.

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

