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

from desktop.lib.django_util import render
from django.http import HttpResponse, HttpResponseRedirect, HttpResponse, HttpResponseServerError
from cdap.client import auth_client
from cdap.conf import CDAP_ROUTER_URI, CDAP_API_VERSION, CDAP_REST_APIS
from libsentry.api2 import get_api

from collections import defaultdict
import json
import logging

LOG = logging.getLogger(__name__)
CDAP_CLIENT = auth_client(CDAP_ROUTER_URI.get(), CDAP_API_VERSION.get())
ENTITIES_DETAIL = dict()


##############################################################
# Localized helper functions defined here
##############################################################

def cdap_error_handler(func):
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


def _fetch_entites_from_cdap(entities, entities_detail):
  # Iter through entities and fetch the name and description
  for namespace in entities:
    for entity_type, entity_url in CDAP_REST_APIS.iteritems():
      full_url = '/namespaces/' + namespace + entity_url
      items = _call_cdap_api(full_url)
      if entity_type == 'application':
        # Application has additional hierarchy
        entities[namespace][entity_type] = {}
        entities_detail[namespace][entity_type] = {}
        for item in items:
          programs = _call_cdap_api(full_url + '/' + item['name'])['programs']
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


##############################################################
# Controller functions goes here
# Routers are defined in urls.py
##############################################################

@cdap_error_handler
def cdap_authenticate(request):
  CDAP_CLIENT.authenticate(request.POST['username'], request.POST['password'])
  return HttpResponse()


@cdap_error_handler
def index(request):
  """
  Request handler for index page. CDAP rest service does not provide api to fetch all entities,
  so call apis hierarchically.
  :return: Json Struct:
  entities: {
    namespace1: {"stream": [], "dataset": [], "artifact": [], "application": [{"type": []}]},
    ...
  }
  """
  global ENTITIES_DETAIL
  # If not authenticate yet, render template to ask for username/password
  if not CDAP_CLIENT.is_set_credentials:
    return render('index.mako', request, dict(date2='testjson', unauthenticated=True))
  # Fetch all the namespaces first
  namespaces = _call_cdap_api('/namespaces')
  entities = dict((ns['name'], dict()) for ns in namespaces)
  entities_detail = dict((ns['name'], ns) for ns in namespaces)
  entities, ENTITIES_DETAIL = _fetch_entites_from_cdap(entities, entities_detail)
  return render('index.mako', request, dict(date2='testjson', entities=entities))


@cdap_error_handler
def details(request, path):
  """
  Return detailed information of the entity with path
  :param path: Path to the entity (namespaceName/.../.../.../)
  :return: Json Struct:  {property1: value, property2: value, ...}
  """
  item = ENTITIES_DETAIL
  for k in path.strip('/').split('/'):
    item = item[k]
  return HttpResponse(json.dumps(item), content_type='application/json')
