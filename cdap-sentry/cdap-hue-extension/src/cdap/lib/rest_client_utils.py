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

import logging


LOG = logging.getLogger(__name__)


class RestClientUtils:
    """
    The utility class for working with rest clients
    """

    @staticmethod
    def verify_response_code(response_code):
        if response_code is hl.OK:
            LOG.debug("Success operation result code.")
            return
        else:
            RestClientUtils.check_status(response_code)

    @staticmethod
    def check_status(status):
        raise {
            hl.NOT_FOUND: RestClientUtils.raise_not_found_error(status),
            hl.BAD_REQUEST: RestClientUtils.raise_bad_request_error(status),
            hl.CONFLICT: RestClientUtils.raise_conflict_error(status),
            hl.UNAUTHORIZED: RestClientUtils.raise_unauthorized_error(status),
            hl.FORBIDDEN: RestClientUtils.raise_forbidden_error(status),
            hl.METHOD_NOT_ALLOWED: RestClientUtils.raise_not_allowed(status),
            hl.INTERNAL_SERVER_ERROR: RestClientUtils.raise_inter_serv_error(
                status)
        }.get(status, RestClientUtils.raise_not_supported_error(status))

    @staticmethod
    def raise_not_found_error(status):
        return NotFoundError(status, u'Not found HTTP code'
                                     u' was received from gateway server.')

    @staticmethod
    def raise_bad_request_error(status):
        return BadRequestError(status, u'Bad request HTTP code '
                                       u'was received from gateway server.')

    @staticmethod
    def raise_conflict_error(status):
        return ConflictError(status, u'Conflict HTTP code was'
                                     u' received from gateway server.')

    @staticmethod
    def raise_unauthorized_error(status):
        return UnauthorizedError(status, u'Authorization error'
                                         u' code was received from server. ')

    @staticmethod
    def raise_forbidden_error(status):
        return ForbiddenError(status, u'Forbidden HTTP code was '
                                      u'received from gateway server')

    @staticmethod
    def raise_not_allowed(status):
        return MethodNotAllowed(status, u'Method not allowed code was '
                                        u'received from gateway server')

    @staticmethod
    def raise_inter_serv_error(status):
        return InternalServerError(status, u'Internal server exception '
                                           u'during operation process. ')

    @staticmethod
    def raise_not_supported_error(status):
        return NotSupportedError(status, u'Operation is '
                                         u'not supported by gateway server')


class BaseHttpError(Exception):
    def __init__(self, code, msg):

        self.__errorCode = code
        self.__errorMsg = msg

    def code(self):
        return self.__errorCode

    def message(self):
        return self.__errorMsg

    def __str__(self):
        return u"Code: %s \nMessage: %s" % (self.__errorCode, self.__errorMsg)


class BadRequestError(BaseHttpError):

    def __init__(self, code, msg):
        super(BadRequestError, self).__init__(code, msg)


class NotFoundError(BaseHttpError):
    def __init__(self, code, msg):
        super(NotFoundError, self).__init__(code, msg)


class ConflictError(BaseHttpError):
    def __init__(self, code, msg):
        super(ConflictError, self).__init__(code, msg)


class UnauthorizedError(BaseHttpError):
    def __init__(self, code, msg):
        super(UnauthorizedError, self).__init__(code, msg)


class ForbiddenError(BaseHttpError):
    def __init__(self, code, msg):
        super(ForbiddenError, self).__init__(code, msg)


class MethodNotAllowed(BaseHttpError):
    def __init__(self, code, msg):
        super(MethodNotAllowed, self).__init__(code, msg)


class InternalServerError(BaseHttpError):
    def __init__(self, code, msg):
        super(InternalServerError, self).__init__(code, msg)


class NotSupportedError(BaseHttpError):
    def __init__(self, code, msg):
        super(NotSupportedError, self).__init__(code, msg)
