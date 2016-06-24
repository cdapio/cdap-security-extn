# -*- coding: utf-8 -*-
# Copyright © 2014 Cask Data, Inc.
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

try:
    import httplib as hl
except ImportError:
    import http.client as hl

import json
import logging
from random import randint
import time
import datetime
import requests
from .access_token import AccessToken

from .authentication_client import AuthenticationClient
from .rest_client_utils import RestClientUtils

LOG = logging.getLogger(__name__)


class AbstractAuthenticationClient(AuthenticationClient):
    """
    Abstract authentication client implementation with common methods.
    """

    ACCESS_TOKEN_KEY = u"access_token"
    AUTH_URI_KEY = u"auth_uri"
    AUTHENTICATION_HEADER_PREFIX_BASIC = u"Basic "
    HTTP_PROTOCOL = u"http"
    HTTPS_PROTOCOL = u"https"
    EXPIRES_IN_KEY = u"expires_in"
    TOKEN_TYPE_KEY = u"token_type"
    SPARE_TIME_IN_MILLIS = 5000

    def __init__(self):
        self.__access_token = None
        self.__auth_enabled = None
        self.__auth_url = None
        self.__base_url = None
        self.__expiration_time = None

    def invalidate_token(self):
        self.__access_token = None

    def is_auth_enabled(self):
        if not self.__auth_enabled:
            self.__auth_url = self.fetch_auth_url()
        self.__auth_enabled = True if self.__auth_url else False
        return self.__auth_enabled

    def set_connection_info(self, host, port, ssl):
        if self.__base_url:
            raise ValueError(u"Connection info is already configured!")
        self.__base_url = u'%s://%s:%d' % (self.HTTPS_PROTOCOL if ssl
                                           else self.HTTP_PROTOCOL, host, port)

    def fetch_auth_url(self):
        """
        Fetches the available authentication server URL, if
        authentication is enabled in the gateway server,
        otherwise, empty string will be returned.

        Return value:
        string value of the authentication server URL
        """
        if self.__base_url is None:
            raise ValueError(u"Base authentication"
                             u" client is not configured!")

        ping_uri = self.__base_url + '/ping'
        LOG.debug(u"Try to get the authentication URI from "
                  u"the gateway server: %s." % ping_uri)

        response = requests.get(ping_uri, verify=self.ssl_verification_status())
        result = None
        if response.status_code == hl.UNAUTHORIZED:
            uri_list = response.json()[self.AUTH_URI_KEY]
            if uri_list:
                result = uri_list[randint(0, (len(uri_list) - 1))]
            else:
                raise IOError("Authentication servers list is empty.")
            return result

    def is_token_expired(self):
        """
        Checks if the access token has expired.

        Return value:
        true, if the access token has expired
        """
        return self.__expiration_time < int(round(time.time() * 1000))

    def get_access_token(self):
        if not self.is_auth_enabled():
            raise IOError(u"Authentication is "
                          u"disabled in the gateway server.")
        if self.__access_token is None or self.is_token_expired():
            request_time = int(round(time.time() * 1000))
            self.__access_token = self.fetch_access_token()
            self.__expiration_time = \
                request_time + self.__access_token.expires_in\
                - self.SPARE_TIME_IN_MILLIS
            LOG.debug(u"Received the access token successfully."
                      u" Expiration date is %s" %
                      datetime.datetime.
                      fromtimestamp(self.__expiration_time/1000)
                      .strftime(u'%Y-%m-%d %H:%M:%S.%f'))
        return self.__access_token

    def execute(self, headers):
        """
        Executes fetch access token request.

        Keyword arguments:
        headers -- headers needed to add to http request

        Return value:
        Object containing the access token
        """
        response = requests.get(self.auth_url,
                                headers=json.loads(headers),
                                verify=self.ssl_verification_status())
        status_code = response.status_code
        RestClientUtils.verify_response_code(status_code)
        token_value = response.json()[self.ACCESS_TOKEN_KEY]
        token_type = response.json()[self.TOKEN_TYPE_KEY]
        expires_in_str = response.json()[self.EXPIRES_IN_KEY]
        if not token_value or not token_type or not expires_in_str:
            raise IOError(u'Unexpected response was'
                          u' received from the authentication server.')
        return AccessToken(token_value, expires_in_str, token_type)

    @property
    def auth_url(self):
        return self.__auth_url
