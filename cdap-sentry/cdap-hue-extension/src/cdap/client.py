#!/usr/bin/env python
# Copyright 2016 Cask Data, Inc.
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


import json
import re
import requests
from cdap.lib import BasicAuthenticationClient


class auth_client:
  """
  An authorization Client to connect to CDAP rest service running on a secure cluster
  It get initialized by client = auth_client("host:port/api_version")
  And user should provide credentials by client.set_credentials(username, password)
   to get the access token of a secure cdap cluster
  Once the token expires, the client will get a new token from the server automatically
  """

  def __init__(self, cdap_host, cdap_router_port, cdap_api_version):
    self._cdap_username = None
    self._cdap_password = None
    self._auth_header = None
    self.is_set_credentials = False
    self.host_url = "http://%s:%d/%s" % (cdap_host, cdap_router_port, cdap_api_version)
    self.client = BasicAuthenticationClient()
    self.client.set_connection_info(cdap_host, cdap_router_port, False)

  def authenticate(self, username=None, password=None):
    if self.client.is_auth_enabled():
      self._cdap_username = username
      self._cdap_password = password
      properties = {
        'security_auth_client_username': username,
        'security_auth_client_password': password,
        'security_ssl_cert_check': True
      }
      self.client.configure(properties)
      token = self.client.get_access_token()
      self._auth_header = {'Authorization': token.token_type + ' ' + token.value}
    self.is_set_credentials = True

  def get(self, url):
    if self.client.is_token_expired():
      # Update the token if is expired
      self.authenticate(self._cdap_username, self._cdap_password)
    return json.loads(requests.get(self.host_url + url, headers=self._auth_header).text)


