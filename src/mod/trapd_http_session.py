# ============LICENSE_START=======================================================
# org.onap.dcae
# ================================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
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
#
# ECOMP is a trademark and service mark of AT&T Intellectual Property.
#
"""
trapd_http_session establishes an http session for future use in publishing
messages to the dmaap cluster.
"""

__docformat__ = 'restructuredtext'

import logging
import os
import requests
import string
import time
import traceback

prog_name = os.path.basename(__file__)


# # # # # # # # # # # # #
# fx: init_session_obj
# # # # # # # # # # # # #
def init_session_obj(_dcae_logger):
    """
    Initializes and returns a http request session object for later use
    :Parameters:
      dcae logger for diagnostics
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
        s = requests.Session()
        _dcae_logger.debug("New requests session has been initialized: %s" % s)
    except:
        _dcae_logger.error("Failed to create new requests session")

    return s
