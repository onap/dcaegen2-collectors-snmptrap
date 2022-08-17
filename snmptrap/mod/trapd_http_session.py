# ============LICENSE_START=======================================================
# Copyright (c) 2017-2022 AT&T Intellectual Property. All rights reserved.
# ================================================================================
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END=========================================================
"""
trapd_http_session establishes an http session for future use in publishing
messages to the dmaap cluster.
"""

__docformat__ = "restructuredtext"

import os
import requests
import traceback
from trapd_io import ecomp_logger, stdout_logger
import trapd_settings as tds
from trapd_exit import cleanup_and_exit

prog_name = os.path.basename(__file__)


# # # # # # # # # # # # #
# fx: init_session_obj
# # # # # # # # # # # # #
def init_session_obj():
    """
    Initializes and returns a http request session object for later use
    :Parameters:
      none
    :Exceptions:
      session object creation
        this function will throw an exception if unable to create
        a new session object
    :Keywords:
      http request session
    :Variables:
      none
    """

    try:
        _loc_session = requests.Session()
    except Exception as e:
        msg = "Unable to create new http session - FATAL ERROR, exiting"
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_FATAL, tds.CODE_GENERAL, msg)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    return _loc_session


# # # # # # # # # # # # #
# fx: close_session_obj
# # # # # # # # # # # # #
def close_session_obj(_loc_http_requ_session):
    """
    Closes existing http request session object
    :Parameters:
      _loc_http_requ_session
    :Exceptions:
      session object creation
        this function will throw an exception if unable to create
        a new session object
    :Keywords:
      http request session
    :Variables:
      none
    """

    # Close existing session if present.
    if _loc_http_requ_session is not None:
        try:
            _loc_http_requ_session.close()
            return True
        except Exception as e:
            msg = "Unable to close current http session - FATAL ERROR, exiting"
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_FATAL, tds.CODE_GENERAL, msg)
            stdout_logger(msg)
            cleanup_and_exit(1, tds.pid_file_name)


# # # # # # # # # # # # #
# fx: reset_session_obj
# # # # # # # # # # # # #
def reset_session_obj(_loc_http_requ_session):
    """
    Closes existing http request session object
    and re-opens with current config vals
    :Parameters:
      _loc_http_requ_session
    :Exceptions:
      session object creation
        this function will throw an exception if unable to create
        a new session object
    :Keywords:
      http request session
    :Variables:
      none
    """

    # close existing http_requ_session if present
    ret = close_session_obj(_loc_http_requ_session)

    # open new http_requ_session
    _loc_http_requ_session = init_session_obj()
    return _loc_http_requ_session
