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

#from desktop.lib.django_util import render
#from django.shortcuts import render, redirect
from desktop.lib.django_util import render
from django.contrib.auth.models import Group
from django.core.cache import get_cache
from django.http import HttpResponse, HttpResponseRedirect, HttpResponse, HttpResponseServerError
from cdap.client import auth_client
from cdap.conf import CDAP_ROUTER_URI, CDAP_API_VERSION, CDAP_REST_APIS
from libsentry.api2 import get_api

from collections import defaultdict
import os
import json
import logging

from django.views.decorators.csrf import requires_csrf_token
from django.shortcuts import render
from django.shortcuts import csrf_protect

LOG = logging.getLogger(__name__)
CDAP_CLIENT = auth_client(CDAP_ROUTER_URI.get(), CDAP_API_VERSION.get())
CACHE = get_cache('default')
ENTITIES_DETAIL_CACHE_KEY = "entities_detail_key"


##############################################################
# Localized helper functions defined here
##############################################################

def _cdap_error_handler(func):
  """
  Decorator to handle exceptions for a controller function
  """

  def wrapped_func(*args, **kwargs):
    try:
      return func(*args, **kwargs)
    except Exception as e:
      LOG.exception(unicode(str(e), 'utf8'))
      return HttpResponseServerError(e, content_type='application/text')

  return wrapped_func


def _call_cdap_api(url):
  return CDAP_CLIENT.get(url)


def _get_sentry_api(user):
  """
  Get the API helper class of sentry
  :param user: The user of the http request. Must be authorized to perform sentry operations (in sentry-site.xml)
  :return: API helper class of sentry. Defined in libsentry/api2.py
  """
  # Here "cdap" stands for the component to be used in sentry.
  # Since here the CDAP plugin only deals with CDAP related ACLs, it is hard coded as "cdap" here
  return get_api(user, "cdap")


def _fetch_entites_from_cdap(entities, entities_detail):
  # Iter through entities and fetch the name and description
  for namespace in entities:
    for entity_type, entity_url in CDAP_REST_APIS.iteritems():
      full_url = os.path.join('namespaces', namespace, entity_url)
      items = _call_cdap_api(full_url)
      if entity_type == 'application':
        # Application has additional hierarchy
        entities[namespace][entity_type] = {}
        entities_detail[namespace][entity_type] = {}
        for item in items:
          programs = _call_cdap_api(os.path.join(full_url, item['name']))['programs']
          program_dict = defaultdict(list)
          for program in programs:
            program_dict[program['type'].lower()].append(program)
          entities[namespace][entity_type][item['name']] = program_dict
          entities_detail[namespace][entity_type][item['name']] = dict((p_type, {p['name']: p})
                                                                       for p_type, programs in program_dict.items()
                                                                       for p in programs)
          entities_detail[namespace][entity_type][item['name']].update(item)
      elif entity_type == 'artifact':
        # Append artifact version to artifact name to be used as identifier
        entities[namespace][entity_type] = [item['name'] + '.' + item['version'] for item in items]
        entities_detail[namespace][entity_type] = dict((item['name'] + '.' + item['version'], item)
                                                       for item in items)
      else:
        entities[namespace][entity_type] = [item['name'] for item in items]
        entities_detail[namespace][entity_type] = dict((item['name'], item) for item in items)
  return entities, entities_detail


def _match_authorizables(base_authorizables, authorizables):
  """
  Method to check if authorizables (entity in CDAP) is contained (the children) of base_authorizables
  If so, base_authorizables should be exactly the same as the leading part of authorizables
  :return: bool: True if match else False
  """
  return authorizables[:len(base_authorizables)] == base_authorizables


def _to_sentry_privilege(action, authorizables):
  return {
    "component": "cdap",
    "serviceName": "cdap",
    "authorizables": authorizables,
    "action": action,
  }


def _path_to_sentry_authorizables(path):
  path = path.strip("/").split("/")
  path = ["instance", "cdap", "namespace"] + path
  return [{"type": path[i].upper(), "name": path[i + 1].lower()} for i in xrange(0, len(path), 2)]


def _sentry_authorizables_to_path(authorizables):
  return "/".join(auth[key] for auth in authorizables for key in ("type", "name"))


def is_cdap_entity_role(role):
  """
  CDAP create roles for entities by default. These roles are in the format of '.namespace', '.program' etc.
  :param role: The role to judge
  :return: bool: if role is a cdap entity role
  """
  return role['name'].startswith(('.artifact', '.application', '.program', '.dataset', 'stream', '.namespace'))


def _filter_list_roles_by_group(api):
  """
  A helper function to filter the CDAP entity roles defined in Sentry and they will not be presented to users.
  """
  roles = api.list_sentry_roles_by_group()
  return filter(lambda role: not is_cdap_entity_role(role), roles)


def _get_privileges_for_path(user, path):
  """
  Get the roles that have privileges on the path. Since Sentry stores entries per principal, we have to
  query all the data to find the matching privileges.
  :param user: The user make the reqeust. Comes from request.user
  :param path: The path of CDAP entitiy
  :return: a Json object contains all the roles that have certain privileges on the entity
  """
  api = _get_sentry_api(user)
  roles = [result["name"] for result in _filter_list_roles_by_group(api)]
  privileges = {}
  authorizable = _path_to_sentry_authorizables(path)
  for role in roles:
    sentry_privilege = api.list_sentry_privileges_by_role("cdap", role)
    for privilege in sentry_privilege:
      if _match_authorizables(privilege["authorizables"], authorizable):
        if role not in privileges:
          privileges[role] = defaultdict(list)
        privileges[role]["actions"].append(privilege["action"])
  return privileges


##############################################################
# Controller functions
# Routers are defined in urls.py
##############################################################

@_cdap_error_handler
def cdap_authenticate(request):
  CDAP_CLIENT.authenticate(request.POST['username'], request.POST['password'])
  return HttpResponse()

@_cdap_error_handler
@csrf_protect
def index(request):
  """
  Request handler for the index page. As the CDAP RESTful service does not provide an API to fetch all of the
  entities, call the APIs hierarchically.
  :return: JSON Struct:
  entities: {
    namespace1: {"stream": [], "dataset": [], "artifact": [], "application": [{"type": []}]},
    ...
  }
  """
  # If not yet authenticated, render a template to ask for the username / password

    #return render('index.mako', request, dict(date2='testjson', unauthenticated=True))
  # Fetch all the namespaces first

  if not CDAP_CLIENT.is_set_credentials:
    return render(request, "index.mako", dict(date2='testjson', unauthenticated=True))

  namespaces = _call_cdap_api('namespaces')
  entities = dict((ns['name'], dict()) for ns in namespaces)
  entities_detail = dict((ns['name'], ns) for ns in namespaces)
  entities, entities_detail = _fetch_entites_from_cdap(entities, entities_detail)

  # Detail informations are stored in entites_detail. Cache it for future requests.
  CACHE.set(ENTITIES_DETAIL_CACHE_KEY, entities_detail)
  #return render('index.mako', request, dict(date2='testjson', entities=entities))
  return render(request, "index.mako", dict(date2='testjson', entities=entities))


@_cdap_error_handler
def details(request, path):
  """
  Returns detailed information on the entity at path.
  :param path: Path to the entity (namespaceName/.../.../.../)
  :return: JSON Struct:  {property1: value, property2: value, ...}
  """
  item = CACHE.get(ENTITIES_DETAIL_CACHE_KEY)
  # ENTITIES_DETAIL : {"namespaceName": {"name":"", "description": "", "stream":{}, "artifact":"", "dataset":"",
  # "application":""}, {}...} Each part in path.split('/') matches the key name in ENTITIES_DETAIL
  # The detailed information of entity at path stores in the last dict
  for k in path.strip('/').split('/'):
    item = item[k]
  item["privileges"] = _get_privileges_for_path(request.user, path)
  return HttpResponse(json.dumps(item), content_type='application/json')


@_cdap_error_handler
def grant_privileges(request):
  """
  Grant a list of actions to an entity. Should be a Post Method.
  :param request: POST DATA{
    "role": name of role,
    "actions": a list/array of actions,
    "path": the path to entity,
  }
  """
  api = _get_sentry_api(request.user)
  role = request.POST["role"]
  actions = request.POST.getlist("actions[]")
  authorizables = _path_to_sentry_authorizables(request.POST["path"])
  for action in actions:
    tSentryPrivilege = _to_sentry_privilege(action, authorizables)
    api.alter_sentry_role_grant_privilege(role, tSentryPrivilege)
  return HttpResponse()


@_cdap_error_handler
def revoke_privileges(request):
  """
  Revoke a list of actions to an entity. Should be a Post Method.
  :param request: POST DATA{
    "role": name of role,
    "actions": a list/array of actions,
    "path": the path to entity,
  }
  :return: If entity privileges cannot be revoked (which indicates the privileges are granted on an entity of higher
  level), return a Json array of where these privileges are defined.
  """
  api = _get_sentry_api(request.user)
  role = request.POST["role"]
  actions = request.POST.getlist("actions[]")
  authorizables = _path_to_sentry_authorizables(request.POST["path"])
  for action in actions:
    tSentryPrivilege = _to_sentry_privilege(action, authorizables)
    api.alter_sentry_role_revoke_privilege(role, tSentryPrivilege)
  # Check if all the privileges are revoked successfully
  response_msgs = [_sentry_authorizables_to_path(privilege["authorizables"])
                   for privilege in api.list_sentry_privileges_by_role("cdap", role)
                   if _match_authorizables(privilege["authorizables"], authorizables)]
  return HttpResponse(json.dumps(response_msgs), content_type="application/json")


@_cdap_error_handler
def list_roles_by_group(request):
  """
  List sentry roles along with group
  :param request:
  :return: A Json struct
    {
      "name": role name,
      "groups": [group1, group2, group3...]
    }
  """
  sentry_privileges = _filter_list_roles_by_group(_get_sentry_api(request.user))
  return HttpResponse(json.dumps(sentry_privileges), content_type="application/json")


@_cdap_error_handler
def list_privileges_by_role(request, role):
  """
  List sentry privilegs by role
  :param request:
  :param role: role name
  :return: A Json array of SentryPrivileges: [p1, p2, p3...]
  """
  sentry_privileges = _get_sentry_api(request.user).list_sentry_privileges_by_role("cdap", role)
  sentry_privileges = [{"actions": p["action"], "authorizables": _sentry_authorizables_to_path(p["authorizables"])}
                       for p in sentry_privileges]
  return HttpResponse(json.dumps(sentry_privileges), content_type="application/json")


@_cdap_error_handler
def list_privileges_by_group(request, group):
  """
  List sentry privileges by group
  :param request:
  :param group: group name
  :return: A Json array of SentryPrivileges: [p1, p2, p3...]
  """
  api = _get_sentry_api(request.user)
  roles = _filter_list_roles_by_group(api)

  # Construct a dictionary like {groupname:[role1,role2,role3]}
  reverse_group_role_dict = defaultdict(list)
  for role in roles:
    for g in role["groups"]:
      reverse_group_role_dict[g].append(role["name"])

  if group in reverse_group_role_dict:
    response = [api.list_sentry_privileges_by_role("cdap", role) for role in reverse_group_role_dict[group]]
  else:
    response = []
  return HttpResponse(json.dumps(response), content_type="application/json")


@_cdap_error_handler
def create_role(request, role_name):
  """
  :param role_name: The name of the role to create
  """
  _get_sentry_api(request.user).create_sentry_role(role_name)
  return HttpResponse("Role %s successfully created." % role_name)


@_cdap_error_handler
def drop_role(request, role_name):
  """
  :param role_name: The name of the role to drop
  """
  _get_sentry_api(request.user).drop_sentry_role(role_name)
  return HttpResponse("Role %s successfully deleted." % role_name)


@_cdap_error_handler
def list_all_groups(request):
  """
  List all groups in Django. Groups can be synced with LDAP/Unix groups with Hue's built-in group tools.
  :return: a json array of all groups' name
  """
  return HttpResponse(json.dumps([group.name for group in Group.objects.all()]), content_type="application/json")


@_cdap_error_handler
def alter_role_by_group(request):
  """
  Alter the groups belonging to a role. Post data should contain the current groups of a role and this function will
  update it in Sentry
  :param request: Post data: {"role": role, "groups[]", [group1, group2, ...]}
  """
  role = request.POST.get("role")
  post_groups = set(request.POST.getlist("groups[]"))
  api = _get_sentry_api(request.user)
  groups = set([item["groups"] for item in _filter_list_roles_by_group(api) if item["name"] == role][0])
  # newly added groups
  api.alter_sentry_role_add_groups(role, post_groups.difference(groups))
  # deleted groups
  api.alter_sentry_role_delete_groups(role, groups.difference(post_groups))
  return HttpResponse("Successfully altered the role to " + str(post_groups))

