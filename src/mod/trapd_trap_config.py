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
trapd_trap_conf reads config file of traps and stores/returns them
in a data dictionary that is used to compare arriving SNMP OID's
to the list contained in this file for a keep(/publish) or ignore
decision.
"""

__docformat__ = 'restructuredtext'

import os
import sys
import string
import time
import traceback
from trapd_exit import cleanup_and_exit


prog_name = os.path.basename(__file__)


# # # # # # # # # # #
# fx: read_trap_config
# # # # # # # # # # #

def read_trap_config(_yc_trap_conf, _dcae_logger):
    """
    Load trap config file specified in yaml conf.  This config (1) specifies
    which traps should be published(inclusion) and which traps should be discarded
    (not present in config) and (2) maps SNMP Notify OID to DMAAP/MR topics
    :Parameters:
      none
    :Exceptions:
      file open
        this function will throw an exception if unable to open
        _yc_trap_conf
    :Keywords:
      NotifyOID trap config topic
    :Variables:
    """

    _trap_conf_dict = {}

    if os.path.isfile(_yc_trap_conf):
        _dcae_logger.debug('Reading trap config file %s ' % _yc_trap_conf)
    else:
        _dcae_logger.error('ERROR:  trap config file %s does NOT exist - exiting'
                           % (_yc_trap_conf))
        cleanup_and_exit(1, "undefined")

    # reset dictionaries in case we've been here before
    _num_trap_conf_entries = 0

    field_separator = " "

    _dcae_logger.debug('processing trap config settings from %s'
                       % (_yc_trap_conf))
    for line in open(_yc_trap_conf):
        # format:
        #
        # oid_including_regex <topic>
        #
        if line[0] != '#':
            columns = line.rstrip().split(field_separator)
            # process trap config entries
            if len(columns) == 2:
                _trap_conf_oid = columns[0]
                _trap_conf_dict[_trap_conf_oid] = columns[1]
                _dcae_logger.debug('%d oid: %s topic: %s' %
                                   (_num_trap_conf_entries, _trap_conf_oid, _trap_conf_dict[_trap_conf_oid]))
                _num_trap_conf_entries += 1
            else:
                _dcae_logger.debug('ERROR: Invalid trap config entry - '
                                   'skipping: %s' % (line.rstrip()))

    _dcae_logger.debug('%d trap config entries found in %s' % (_num_trap_conf_entries,
                                                               _yc_trap_conf))

    return _trap_conf_dict
