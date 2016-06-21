#!/usr/bin/env python
# coding=utf8
# Copyright © 2016 Cask Data, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

# This file is known as router
# Regex is used to match all the urls

from django.conf.urls import patterns, url

urlpatterns = patterns('cdap',
                       url(r'^$', 'views.index'),
                       url(r'^authenticate$', 'views.cdap_authenticate'),
                       url(r'^details/(?P<path>.+)/$', 'views.details'),
                       # TODO: Implement the following apis
                       # url(r'^list_roles_by_group', 'views.list_roles_by_group'),
                       # url(r'^list_privileges_by_role/(?P<role>.+)/', 'views.list_privileges_by_role'),
                       # url(r'^list_privileges_by_group/(?P<group>.+)/', 'views.list_privileges_by_group'),
                       # url(r'^list_privileges_by_authorizable', 'views.list_privileges_by_authorizable'),
                       # url(r'^grant', 'views.grant_privileges'),
                       # url(r'^revoke', 'views.revoke_privileges'),
                       )
