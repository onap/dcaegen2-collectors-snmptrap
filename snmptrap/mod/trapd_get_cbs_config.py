# ============LICENSE_START=======================================================
# Copyright (c) 2018-2022 AT&T Intellectual Property. All rights reserved.
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
Look for CBS broker and return application config; if not present, look for
env variable that specifies JSON equiv of CBS config (typically used for
testing purposes)
"""

__docformat__ = "restructuredtext"

import json
import os
import sys
import string
import time
import traceback
import collections

import trapd_settings as tds
from onap_dcae_cbs_docker_client.client import get_config
from trapd_exit import cleanup_and_exit
from trapd_io import stdout_logger

prog_name = os.path.basename(__file__)


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# function: trapd_get_config_sim
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def get_cbs_config():
    """
    Get config values from CBS or JSON file (fallback)
    :Parameters:
      none
    :Exceptions:
    """

    tds.c_config = {}

    # See if we are in a config binding service (CBS) /controller environment
    try:
        tds.c_config = get_config()
        if tds.c_config == {}:
            msg = "Unable to fetch CBS config or it is erroneously empty - trying override/simulator config"
            stdout_logger(msg)

    # if no CBS present, default to JSON config specified via CBS_SIM_JSON env var
    except Exception as e:
        msg = "ONAP controller not present, trying json config override via CBS_SIM_JSON env variable"
        stdout_logger(msg)

        _cbs_sim_json_file = os.getenv("CBS_SIM_JSON")

        if _cbs_sim_json_file is None:
            msg = "CBS_SIM_JSON not defined - FATAL ERROR, exiting"
            stdout_logger(msg)
            cleanup_and_exit(1, None)

        msg = "ONAP controller override specified via CBS_SIM_JSON: %s" % _cbs_sim_json_file
        stdout_logger(msg)
        try:
            tds.c_config = json.load(open(_cbs_sim_json_file))
            msg = "%s loaded and parsed successfully" % _cbs_sim_json_file
            stdout_logger(msg)
        except Exception as e:
            msg = "Unable to load CBS_SIM_JSON " + _cbs_sim_json_file + " (invalid json?) - FATAL ERROR, exiting"
            stdout_logger(msg)
            cleanup_and_exit(1, None)

    # display consul config returned, regardless of source
    msg = "cbs config: %s" % json.dumps(tds.c_config)
    stdout_logger(msg)

    # recalc timeout, set default if not present
    try:
        tds.timeout_seconds = float(tds.c_config["publisher"]["http_milliseconds_timeout"] / 1000.0)
    except Exception as e:
        tds.timeout_seconds = float(1.5)

    # recalc seconds_between_retries, set default if not present
    try:
        tds.seconds_between_retries = float(tds.c_config["publisher"]["http_milliseconds_between_retries"] / 1000.0)
    except Exception as e:
        tds.seconds_between_retries = float(0.750)

    # recalc min_severity_to_log, set default if not present
    try:
        tds.minimum_severity_to_log = int(tds.c_config["files"]["minimum_severity_to_log"])
    except Exception as e:
        tds.minimum_severity_to_log = int(3)

    try:
        tds.publisher_retries = int(tds.c_config["publisher"]["http_retries"])
    except Exception as e:
        tds.publisher_retries = int(2)

    return True
