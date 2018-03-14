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
Look for CBS broker and return application config; if not present, look for
env variable that specifies JSON equiv of CBS config (typically used for 
testing purposes)
"""

__docformat__ = 'restructuredtext'

import json
import os
import sys
import string
import time
import traceback
import collections

from onap_dcae_cbs_docker_client.client import get_config
from trapd_exit import cleanup_and_exit
from trapd_logging import stdout_logger

prog_name = os.path.basename(__file__)


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# function: trapd_get_config_sim
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def trapd_get_cbs_config():
    """
    Get config values from CBS or JSON file (fallback)
    :Parameters:
      none
    :Exceptions:
    """

    _c_config = {}

    # See if we are in a config binding service (CBS) /controller environment
    try:
        _c_config = get_config()
        if _c_config == {}:
            msg = "Unable to fetch CBS config or it is erroneously empty - trying override/simulator config"
            stdout_logger(msg)
    
    # if no CBS present, default to JSON config specified via CBS_SIM_JSON env var
    except Exception as e:
        msg = "ONAP controller not present, trying json config override via CBS_SIM_JSON env variable"
        stdout_logger(msg)
    
        try:
            cbs_sim_json_file = os.getenv("CBS_SIM_JSON", "None")
        except Exception as e:
            msg = "CBS_SIM_JSON not defined - FATAL ERROR, exiting"
            stdout_logger(msg)
            cleanup_and_exit(1, pid_file_name)
    
        if cbs_sim_json_file == "None":
            msg = "CBS_SIM_JSON not defined - FATAL ERROR, exiting"
            stdout_logger(msg)
            cleanup_and_exit(1, pid_file_name)
        else:
            msg = ("ONAP controller override specified via CBS_SIM_JSON: %s" % cbs_sim_json_file )
            stdout_logger(msg)
            try:
                _c_config = json.load(open(cbs_sim_json_file))
            except Exception as e:
                msg = "Unable to load CBS_SIM_JSON " + cbs_sim_json_file + " (invalid json?) - FATAL ERROR, exiting"
                stdout_logger(msg)
                cleanup_and_exit(1, pid_file_name)

    return _c_config
