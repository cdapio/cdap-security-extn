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


import json
import re
import requests
from cdap_auth_client import BasicAuthenticationClient


class ExtendedAuthenticationClient(BasicAuthenticationClient):
  def clear_config(self):
    """
    Clears the configs in the AuthenticationClient for use
    where the user provides incorrect credentials the first time.
    """
    self._BasicAuthenticationClient__username = None
    self._BasicAuthenticationClient__password = None


class auth_client:
  """
  A wrapper of the authentication client from the cdap_auth_client package for connecting to a secure CDAP cluster.
  It is initialized using:
    client = auth_client("http://host:port", api_version)
  And user should provide credentials by client.authenticate(username, password)
    to get the access token of a secure cdap cluster
  Once the token expires, the client will get a new token from the server automatically
  """

  def __init__(self, cdap_router_uri, cdap_api_version):
    self._cdap_username = None
    self._cdap_password = None
    self._auth_header = None
    self.is_set_credentials = False
    self.host_url = "%s/%s/" % (cdap_router_uri, cdap_api_version)
    self.client = ExtendedAuthenticationClient()
    cdap_host, cdap_router_port = re.sub('^https?://', '', cdap_router_uri).strip('/').split(':')
    self.client.set_connection_info(cdap_host, int(cdap_router_port), False)

  def authenticate(self, username=None, password=None):
    """
    Fetch access token using username and password. If on an insecure cluster, skip this process.
    Leave all the excpetions to be caught outside this function.
    """
    if self.client.is_auth_enabled():
      properties = {
        'security_auth_client_username': username,
        'security_auth_client_password': password,
        'security_ssl_cert_check': True,
      }
      self.client.clear_config()
      self.client.configure(properties)
      self._set_access_token()
    self.is_set_credentials = True

  def _set_access_token(self):
    token = self.client.get_access_token()
    self._auth_header = {'Authorization': token.token_type + ' ' + token.value}

  def get(self, url):
    """
    Get data from certain rest endpoint
    :return: Json Object
    """
    if self.client.is_token_expired():
      # Update the token if is expired
      self._set_access_token()
    return json.loads(requests.get(self.host_url + url.strip('/'), headers=self._auth_header).text)
