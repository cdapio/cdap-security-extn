#!/usr/bin/env python

import logging
import os.path
import sys

from django.utils.translation import ugettext_lazy as _t, ugettext as _

from desktop.conf import default_ssl_cacerts, default_ssl_validate, AUTH_PASSWORD as DEFAULT_AUTH_PASSWORD,\
  AUTH_USERNAME as DEFAULT_AUTH_USERNAME
from desktop.lib.conf import ConfigSection, Config, coerce_bool, coerce_csv, coerce_password_from_script
from desktop.lib.exceptions import StructuredThriftTransportException


LOG = logging.getLogger(__name__)



CDAP_API_HOST = Config(
    key="cdap_api_host",
    help=_t("Host where CDAP rest api service is running. Different from the cdap ui server"),
    default="10.128.0.7"
)

CDAP_API_PORT = Config(
  key="cdap_api_port",
  help=_t("Configure the port the cdap api server runs on."),
  default=10000,
  type=int)

CDAP_API_VERSION = Config(
    key="cdap_api_version",
    help=_t("Specify the cdap api version"),
    default="v3",
)
