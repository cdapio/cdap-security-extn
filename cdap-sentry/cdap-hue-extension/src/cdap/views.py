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
from cdap.conf import CDAP_ROUTER_URI, CDAP_API_VERSION
from libsentry.api2 import get_api

import json
import logging
import re

LOG = logging.getLogger(__name__)
CDAP_CLIENT = auth_client(CDAP_ROUTER_URI.get(), CDAP_API_VERSION.get())
ENTITIES_ALL = dict()


##############################################################
# Localized helper functions defined here
##############################################################

def _call_cdap_api(url):
  return CDAP_CLIENT.get(url)


##############################################################
# Router related functions goes here
# Named as controllers in other MVC frameworks
# Routers are defined in urls.py
##############################################################

def cdap_authenticate(request):
  try:
    CDAP_CLIENT.authenticate(request.POST["username"], request.POST["password"])
    return HttpResponse()
  except Exception as e:
    return HttpResponseServerError(e, content_type="application/text")


def index(request):
  global ENTITIES_ALL
  if not CDAP_CLIENT.is_set_credentials:
    return render('index.mako', request, dict(date2="testjson", unauthenticated=True))
  return render('index.mako', request, dict(date2="testjson"))
