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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class AuthenticationClient(object):
    """
     The client interface to fetch access token from the authentication server.
    """
    @abc.abstractmethod
    def configure(self, properties):
        """
        Configures the authentication client and can be
        called only once for every AuthenticationClient object

        Keyword arguments:
        properties -- A dictionary which holds the configuration
        for authentication client which includes credentials and
        some additional properties, if needed.
        """
        return

    @abc.abstractmethod
    def get_access_token(self):
        """
        Retrieves the access token generated according to the credentials
        required by the authentication provider
        in the authentication server. The access token
        will be cached until its expiry.

        Return value:
        AccessToken object containing the access token
        """
        return

    @abc.abstractmethod
    def is_auth_enabled(self):
        """
        Checks if authentication is enabled on the gateway server.

        Return value:
        True if authentication is enabled
        """
        return

    @abc.abstractmethod
    def set_connection_info(self, host, port, ssl):
        """
        Configures gateway server information.

        Keyword arguments:
        host -- the gateway server host
        port -- the gateway server port
        ssl -- true, if SSL is enabled in the gateway server
        """
        return

    @abc.abstractmethod
    def get_required_credentials(self):
        """
        Provides credentials which are required by the authentication provider
        on authentication server.
        Interactive clients can use this list to obtain credentials
        from the user, and then run
        AuthenticationClient#configure(Properties).

        Return value:
        list of Credential objects for authentication
        """
        return

    @abc.abstractmethod
    def ssl_verification_status(self):
        """
        Check if ssl certificates verification is enabled

        Return value:
        True  if authentication verification is enabled
        """
        return

    @abc.abstractmethod
    def invalidate_token(self):
        """
        Invalidate the cached access token.
        """
        return
