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

from cdap.conf import CDAP_HOST, CDAP_ROUTER_PORT, CDAP_API_VERSION, CDAP_USERNAME, CDAP_PASSWORD
from cdap.src.cdap.client import auth_client
from desktop.lib.conf import ConfigSection, Config

import re
import sys


class test_auth_client_api:
  def __init__(self):
    self.username = CDAP_USERNAME.get()
    self.password = CDAP_PASSWORD.get()
    pass

  def test_set_credentials(self):
    """
    Give correct credentials
    :return:
    """
    STRIPPED_CDAP_API_HOST = re.sub("^http://", "", CDAP_HOST.get())
    client = auth_client(STRIPPED_CDAP_API_HOST, CDAP_ROUTER_PORT.get(), CDAP_API_VERSION.get())
    client.authenticate(self.username, self.password)
    assert client.is_set_credentials == True
    assert type(client.get("/namespaces")) == list

  def test_set_credentials_incorrect(self):
    """
    Test incorrect credentials
    :return:
    """
    STRIPPED_CDAP_API_HOST = re.sub("^http://", "", CDAP_HOST.get())
    client = auth_client(STRIPPED_CDAP_API_HOST, CDAP_ROUTER_PORT.get(), CDAP_API_VERSION.get())
    try:
      client.authenticate("wrong_username", "wrong_password")
    except Exception as e:
      # Should return 401 unauthorized error
      assert "401" in str(e)
    assert client.is_set_credentials == False

  def test_set_credentials_wrong_host(self):
    """
    Test incorrect credentials
    :return:
    """
    client = auth_client("http://non-existing.host.com", 6666, "v3")
    try:
      client.authenticate(self.username, self.password)
    except Exception as e:
      # Should inform hostname error
      assert "[Errno 8] nodename nor servname provided, or not known" in str(e)
    assert client.is_set_credentials == False



import requests
from desktop.lib.django_test_util import make_logged_in_client

class test_rest_apis:
  def __init__(self):
    self.client = make_logged_in_client(username="test", password="test", is_superuser=True)

  def test_another(self):
    response = self.client.get("/cdap/list_roles_by_group")
    print response.content
    print response
    assert False