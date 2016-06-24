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


class AccessToken:
    """
    This class represents access token object.
    """

    def __init__(self, value, expires_in, token_type):
        self.__value = value
        self.__expires_in = expires_in
        self.__token_type = token_type
    pass

    @property
    def value(self):
        return self.__value

    @property
    def expires_in(self):
        return self.__expires_in

    @property
    def token_type(self):
        return self.__token_type
