# ============LICENSE_START=======================================================
# org.onap.dcae
# ================================================================================
# Copyright (c) 2018 AT&T Intellectual Property. All rights reserved.
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
NOTE:  This module is for temporary use.  It will be removed when dcae_snmptrapd
is migrated to the new controller infrastructure.

trapd_dmaap_config is responsible for reading/parsing the previous generation
'dmaap.conf' file, which includes stream, server and authentication details for
publishing activities.
"""

__docformat__ = 'restructuredtext'

import os
import sys
import string
import time
import traceback
import collections
import json

from trapd_exit import cleanup_and_exit

prog_name = os.path.basename(__file__)


# # # # # # # # # # #
# fx: read_dmaap_config
# # # # # # # # # # #
def read_dmaap_config(_yc_dmaap_conf, _dcae_logger):
    # FIXME NOTE: This is for testing purposes only, and utilizes the
    # previous generation of the controller; dispose of when ready
    """
    Load dmaap config /etc/dcae/dmaap.conf file (legacy controller)
    :Parameters:
      name of dmaap config file
    :Exceptions:
      file open
        this function will throw an exception if unable to open
        yc_dmaap_conf(fatal error)
    :Keywords:
      legacy controller dmaap.conf
    :Variables:
      yc_dmaap_conf
        full path filename of dmaap_conf file provided by previous
        generation controller
    :Returns:
      named tuple of config values
    """

    _dmaap_cfg_values_nt = collections.namedtuple('dmaap_config_values', [
                                                  'dmaap_url', 'dmaap_user_name', 'dmaap_p_var', 'dmaap_stream_id', 'dmaap_host'])
    if os.path.isfile(_yc_dmaap_conf):
        _dcae_logger.debug('Reading DMaaP config file %s ' %
                           _yc_dmaap_conf)
    else:
        _dcae_logger.error('DMaaP config file %s does NOT exist - exiting'
                           % (_yc_dmaap_conf))
        cleanup_and_exit(1, undefined)

    with open(_yc_dmaap_conf) as _dmaap_config_fd:
        _dmaapCfgData = json.load(_dmaap_config_fd)

    try:
        dmaap_url = _dmaapCfgData[0]["dmaapUrl"]
        _dcae_logger.debug('dmaap_url: %s' % (dmaap_url))
        dmaap_user_name = _dmaapCfgData[0]["dmaapUserName"]
        _dcae_logger.debug('dmaap_user_name: %s' % (dmaap_user_name))
        dmaap_p_var = _dmaapCfgData[0]["dmaapPassword"]
        _dcae_logger.debug('dmaap_p_var: -')
        dmaap_stream_id = _dmaapCfgData[0]["dmaapStreamId"]
        _dcae_logger.debug('dmaap_stream_id: %s' % (dmaap_stream_id))
    except:
        _dcae_logger.error('DMaaP config file %s has missing data - exiting'
                           % (_yc_dmaap_conf))
        cleanup_and_exit(1, "undefined")

    # This is for logging purposes only.
    dmaap_host = dmaap_url.split('/')[2][:-5]
    _dcae_logger.debug('dmaap_host: %s' % (dmaap_host))

    _dmaap_config_fd.close()

    _dmaap_cfg_values = _dmaap_cfg_values_nt(dmaap_url=dmaap_url, dmaap_user_name=dmaap_user_name,
                                             dmaap_p_var=dmaap_p_var, dmaap_stream_id=dmaap_stream_id, dmaap_host=dmaap_host)
    return _dmaap_cfg_values
