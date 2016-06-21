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

# This file parse the configs defined in section [cdap] in Hue's config file


import logging
import os.path
import sys

from django.utils.translation import ugettext_lazy as _t, ugettext as _

from desktop.conf import default_ssl_cacerts, default_ssl_validate, AUTH_PASSWORD as DEFAULT_AUTH_PASSWORD, \
  AUTH_USERNAME as DEFAULT_AUTH_USERNAME
from desktop.lib.conf import ConfigSection, Config

LOG = logging.getLogger(__name__)

CDAP_ROUTER_URI = Config(
  key='cdap_router_uri',
  help=_t('Fully qualified URI to CDAP Router. eg. http://localhost:10000'),
  default='http://localhost:10000'
)

CDAP_API_VERSION = Config(
  key="cdap_api_version",
  help=_t("Specify the cdap api version"),
  default="v3",
)
