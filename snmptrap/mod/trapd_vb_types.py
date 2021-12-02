# ============LICENSE_START=======================================================
# Copyright (c) 2018-2021 AT&T Intellectual Property. All rights reserved.
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
module for converting varbind types from Net-SNMP to PYSNMP

- converts pysnmp vb type name to net-snmp for backward compatibility

"""

__docformat__ = "restructuredtext"

import json
import os
import sys
import string
import time
import traceback
import collections
import pprint

import trapd_settings as tds
from trapd_exit import cleanup_and_exit
from trapd_io import stdout_logger, ecomp_logger

prog_name = os.path.basename(__file__)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# module: load_snmpv3_credentials
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

_pysnmp_to_netsnmp_vb_type = {
    "Integer32": "integer",
    "Integer": "integer",
    "Gauge32": "unsigned",
    "Counter32": "counter32",
    "OctetString": "octet",
    "py_type_5": "hex",
    "py_type_6": "decimal",
    "Null": "null",
    "ObjectIdentifier": "oid",
    "TimeTicks": "timeticks",
    "IpAddress": "ipaddress",
    "Bits": "bits",
}

default_vb_type = "octet"


def pysnmp_to_netsnmp_varbind_convert(_pysnmp_vb_type):
    """
    Convert pysnmp varbind types to Net-SNMP nomenclature
    to maintain backward compatibilty with existing solutions
    :Parameters:
      _pysnmp_vb_type: varbind type as presented from pysnmp
      API
    :Exceptions:
      if _pysnmp_vb_type isn't found in dictionary, return
      type that was defined by pysnmp in original call
    """

    # lookup _pysnmp_vb_type in conversion dictionary
    try:
        _netsnmp_vb_type = _pysnmp_to_netsnmp_vb_type[_pysnmp_vb_type]
        return _netsnmp_vb_type
    except Exception as e:
        # if not found, return original pysnmp type
        msg = "%s not configured as pysnmp varbind type - returning %s" % (_pysnmp_vb_type, default_vb_type)
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        return default_vb_type
