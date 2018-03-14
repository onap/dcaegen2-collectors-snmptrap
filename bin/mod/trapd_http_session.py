# ============LICENSE_START=======================================================
# org.onap.dcae
# ================================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
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

import os
import requests
import traceback

# snmptrapd
import trapd_settings

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
        return None

    return _loc_session
