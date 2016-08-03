=========================
CDAP Integration with Hue
=========================

Overview
========

This project provides integration between CDAP and Cloudera Hue via a Hue plugin, providing users
the ability to explore CDAP entities and manage ACLs of these entities through Hue's UI. 

The CDAP integration is a separate app in Hue, providing separate routing namespace and request 
handlers from existing Hue functionality. 

This plugin communicates with CDAP and Sentry via HTTP REST/Thrift service calls.

Requirements
============
* HUE 3.10+
* CDAP 3.4+ 

Note: Earlier versions of Hue and CDAP might also work but haven't been tested yet.


Main Stack
==========
* Python 
* Django
* Mako
* Jquery
* Bootstrap


Installation
============

Build
-----
To install and activate the cdap plugin for Hue::

  $ ln -s cdap-security-extn/cdap-sentry/cdap-hue-extension $HUE_HOME/cdap
  $ cd $HUE_HOME
  $ tools/app_reg/app_reg.py --install cdap --relative-paths
  $ chown -R hue: cdap/  # Or chown to the user that will start Hue
  $ sudo $HUE_HOME/build/env/bin/python $HUE_HOME/build/env/bin/pip install cdap-auth-client

Note: If your Hue comes with Cloudera Manager, then HUE_HOME should be set natively. 

If you choose to build Hue from source code, HUE_HOME should be set to the directory of your Hue project.

Configuration
-------------
Configs needed in hue.ini::

  [cdap]
    # Configuration of cdap
    # If HA is enabled for cdap, simply provide configs of any of the router
    # cdap_host=fully-qualified-hostname
    # cdap_router_port=10000
    # cdap_api_version=v3

  [libsentry]
    # Hostname or IP of Sentry server.
    # If HA is enabled for sentry, skip the hostname and port configs below and Hue will read all related configs from sentry-site.xml
    # hostname=fully-qualified-hostname

    # Port the sentry service is running on.
    # port=8038

    # Sentry configuration directory, where sentry-site.xml is located.
    # Make sure user starting the Hue (usually hue) has read privileges on the directory
    # sentry_conf_dir=$SENTRY_HOME/conf   # SENTRY_HOME refers to the directory where sentry is installed

  [[kerberos]]
    # Path to Hue's Kerberos keytab file
    # hue_keytab=
    # Kerberos principal name for Hue
    # hue_principal=hue/hostname.foo.com
    # Path to kinit (binary file of kinit command that comes when kerberos client is installed)
    # kinit_path=/path/to/kinit

Note: If security feature is enabled, you should use fully-qualified hostname rather than 
localhost or 127.0.0.1 in the configs above when Hue is running on the same machine with CDAP. 


Project Details
===============

Directory Structure
-------------------

Here is the file structure of CDAP plugin::

  .
  ├── Makefile	 file used by app_reg.py command, related to plugin installation
  ├── setup.cfg	 setup files for pep8 style check. Use "pep8 ." command to start style check
  ├── setup.py     file used by app_reg.py command, configuration info(name, author etc.) defined here
  ├── src          contains all source code
  │   ├── cdap
  │   │   ├── client.py		an authorization client built based upon python cdap-auth-client
  │   │   ├── conf.py       file to parse all the configurations defined in hue.ini
  │   │   ├── forms.py      files to validate all submitted forms, currently empty since no forms are defined. But Hue needs this file to start the CDAP plugin
  │   │   ├── models.py     files to define database related structure, i.e. table schema, currently empty since CDAP plugin does not store any data in the database. But Hue also needs this file to start the CDAP plugin
  │   │   ├── settings.py   customized settings for CDAP plugin including app name, icon, menu etc., used by Django
  │   │   ├── static
  │   │   │   └── cdap
  │   │   │       ├── art      contains all the icons of CDAP plugin, defined in settings.py
  │   │   │       │   ├── cdap.png
  │   │   │       │   ├── icon_cdap_24.png
  │   │   │       │   └── icon_cdap_48.png
  │   │   │       ├── css
  │   │   │       │   └── cdap.css    css file for CDAP
  │   │   │       └── js
  │   │   │           └── cdap.js    JavaScript file for CDAP
  │   │   ├── templates
  │   │   │   ├── index.mako    Mako template for the main page of CDAP plugin
  │   │   │   └── shared_components.mako    banner, navigation bar, footer defined here
  │   │   ├── urls.py		routers of CDAP, starts with /cdap/..., use regex to match all urls
  │   │   ├── views.py	controllers of CDAP


Backend Design
--------------

The backend code in this CDAP app is splited into two parts, and they are defined in different sections in src/views.py:

1. Talking to CDAP restful service to list CDAP entities. This part of code take advantage of
auth_client and load all related CDAP entites once a user starts to use the app. 

2. Talking to Sentry server to add/delete roles and alter sentry privileges. 
This part of code take advantage of Hue's built in sentry client code defined in $HUE_HOME/desktop/libs/libsentry/api2.py. 
All the related data structure required to use these apis are documented in the comments. 
All these functions are wrapped into backend apis and are hit by front-end via ajax call.




License
=======

Copyright © 2016 Cask Data, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
