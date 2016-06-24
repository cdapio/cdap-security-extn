#!/usr/bin/env python
# Licensed to Cloudera, Inc. under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  Cloudera, Inc. licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from django.conf.urls import patterns, url

urlpatterns = patterns('cdap',
  url(r'^$', 'views.index'),
  url(r'^details/(?P<path>.+)/$', 'views.details'),
  url(r'^authenticate$', 'views.cdap_authenticate'),
  url(r'^list_roles_by_group', 'views.list_roles_by_group'),
  url(r'^list_privileges_by_role/(?P<role>.+)/', 'views.list_privileges_by_role'),
  url(r'^list_privileges_by_group/(?P<group>.+)/', 'views.list_privileges_by_group'),
  url(r'^list_privileges_by_authorizable', 'views.list_privileges_by_authorizable'),
  url(r'^grant', 'views.grant_privileges'),
  url(r'^revoke', 'views.revoke_privileges'),
  url(r'^create_role/(?P<role_name>.+)/', 'views.create_role'),
  url(r'^drop_role/(?P<role_name>.+)/', 'views.drop_role'),
  url(r'^list_all_groups/', 'views.list_all_groups'),
  url(r'^alter_role_by_group', 'views.alter_role_by_group'),
)