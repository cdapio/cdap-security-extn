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

import base64
import logging
import json
from .abstract_authentication_client import AbstractAuthenticationClient
from .credential import Credential

LOG = logging.getLogger(__name__)


class BasicAuthenticationClient(AbstractAuthenticationClient):

    USERNAME_PROP_NAME = u'security_auth_client_username'
    PASSWORD_PROP_NAME = u'security_auth_client_password'
    VERIFY_CERT_PROP_NAME = u'security_ssl_cert_check'
    DEFAULT_VERIFY_SSL_CERT = True

    def __init__(self):
        super(BasicAuthenticationClient, self).__init__()
        self.__username = None
        self.__password = None
        self.__security_ssl_cert_check = False
        self.__credentials = (Credential(self.USERNAME_PROP_NAME,
                                         u'Username for basic authentication.',
                                         False),
                              Credential(self.PASSWORD_PROP_NAME,
                                         u'Password for basic authentication.',
                                         True))

    @property
    def username(self):
        return self.__username

    @username.setter
    def username(self, username):
        self.__username = username

    @property
    def password(self):
        return self.__password

    @password.setter
    def password(self, password):
        self.__password = password

    def get_required_credentials(self):
        return self.__credentials

    def fetch_access_token(self):
        if not self.__username or not self.__password:
            raise ValueError(u'Base authentication client'
                             u' is not configured!')
        LOG.debug(u'Authentication is enabled in the gateway server.'
                  u' Authentication URI %s.' % self.auth_url)
        base64string = base64.b64encode(
            (u'%s:%s' % (self.__username, self.__password)).encode('utf-8'))
        auth_header = json.dumps(
            {u"Authorization": u"Basic %s" % base64string.decode('utf-8')})

        return self.execute(auth_header)

    def ssl_verification_status(self):
        return self.__security_ssl_cert_check

    def configure(self, properties):
        if self.__username or self.__password:
            raise ValueError(u'Client is already configured!')

        self.__username = properties.get(self.USERNAME_PROP_NAME)
        if not self.__username:
            raise ValueError(u'The username property cannot be empty.')

        self.__password = properties.get(self.PASSWORD_PROP_NAME)
        if not self.__password:
            raise ValueError(u'The password property cannot be empty.')

        self.__security_ssl_cert_check = properties.get(self.VERIFY_CERT_PROP_NAME, self.DEFAULT_VERIFY_SSL_CERT)
