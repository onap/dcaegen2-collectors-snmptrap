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
module for snmpv3 support

- loads various USM values for engineID/users

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

from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c

import trapd_settings as tds
from trapd_exit import cleanup_and_exit
from trapd_io import stdout_logger, ecomp_logger

prog_name = os.path.basename(__file__)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# module: load_snmpv3_credentials
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def load_snmpv3_credentials(_py_config, _snmp_engine, _cbs_config):
    """
    Add V3 credentials from CBS config to receiver config
    so traps will be recieved from specified engines/users
    :Parameters:
      _config: snmp entity config
    :Exceptions:
    """

    # add V3 credentials from CBS json structure to running config
    try:
        v3_users = _cbs_config["snmpv3_config"]["usm_users"]
    except Exception as e:
        msg = "No V3 users defined"
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        return _py_config, _snmp_engine

    for v3_user in v3_users:

        # engineId
        try:
            ctx_engine_id = v3_user["engineId"]
        except Exception as e:
            ctx_engine_id = None

        # user
        try:
            userName = v3_user["user"]
        except Exception as e:
            userName = None

        # authorization
        #     find options at -> site-packages/pysnmp/entity/config.py
        # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

        # usmHMACMD5AuthProtocol
        try:
            authKey = v3_user["usmHMACMD5AuthProtocol"]
            authProtocol = config.usmHMACMD5AuthProtocol
        except Exception as e:
            try:
                authKey = v3_user["usmHMACSHAAuthProtocol"]
                authProtocol = config.usmHMACSHAAuthProtocol
            except Exception as e:
                try:
                    authKey = v3_user["usmHMAC128SHA224AuthProtocol"]
                    authProtocol = config.usmHMAC128SHA224AuthProtocol
                except Exception as e:
                    try:
                        authKey = v3_user["usmHMAC192SHA256AuthProtocol"]
                        authProtocol = config.usmHMAC192SHA256AuthProtocol
                    except Exception as e:
                        try:
                            authKey = v3_user["usmHMAC256SHA384AuthProtocol"]
                            authProtocol = config.usmHMAC256SHA384AuthProtocol
                        except Exception as e:
                            try:
                                authKey = v3_user["usmHMAC384SHA512AuthProtocol"]
                                authProtocol = config.usmHMAC384SHA512AuthProtocol
                            except Exception as e:
                                try:
                                    authKey = v3_user["usmNoAuthProtocol"]
                                    authProtocol = config.usmNoAuthProtocol
                                except Exception as e:
                                    # FMDL:  default to NoAuth, or error/skip entry?
                                    msg = "No auth specified for user %s ?" % (userName)
                                    authKey = None
                                    authProtocol = config.usmNoAuthProtocol
                                    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

        # privacy
        #     find options at -> site-packages/pysnmp/entity/config.py
        # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

        # usm3DESEDEPriv
        try:
            privKey = v3_user["usm3DESEDEPrivProtocol"]
            privProtocol = config.usm3DESEDEPrivProtocol
        except Exception as e:
            # usmAesCfb128Protocol
            try:
                privKey = v3_user["usmAesCfb128Protocol"]
                privProtocol = config.usmAesCfb128Protocol
            except Exception as e:
                # usmAesCfb192Protocol
                try:
                    privKey = v3_user["usmAesCfb192Protocol"]
                    privProtocol = config.usmAesCfb192Protocol
                except Exception as e:
                    # usmAesBlumenthalCfb192Protocol
                    try:
                        privKey = v3_user["usmAesBlumenthalCfb192Protocol"]
                        privProtocol = config.usmAesBlumenthalCfb192Protocol
                    except Exception as e:
                        # usmAesCfb256Protocol
                        try:
                            privKey = v3_user["usmAesCfb256Protocol"]
                            privProtocol = config.usmAesCfb256Protocol
                        except Exception as e:
                            # usmAesBlumenthalCfb256Protocol
                            try:
                                privKey = v3_user["usmAesBlumenthalCfb256Protocol"]
                                privProtocol = config.usmAesBlumenthalCfb256Protocol
                            except Exception as e:
                                # usmDESPrivProtocol
                                try:
                                    privKey = v3_user["usmDESPrivProtocol"]
                                    privProtocol = config.usmDESPrivProtocol
                                except Exception as e:
                                    # usmNoPrivProtocol
                                    try:
                                        privKey = v3_user["usmNoPrivProtocol"]
                                        privProtocol = config.usmNoPrivProtocol
                                    except Exception as e:
                                        # FMDL:  default to NoPriv, or error/skip entry?
                                        msg = "No priv specified for user %s" % (userName)
                                        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
                                        privKey = None
                                        privProtocol = config.usmNoPrivProtocol
                                        # break

        # msg = ("userName: %s authKey: %s authProtocol: %s privKey: %s privProtocol: %s engineId: %s % (userName, authKey, authProtocol, privKey, privProtocol, ctx_engine_id))
        msg = "userName: %s authKey: **** authProtocol: %s privKey: **** privProtocol: %s engineId: ****" % (
            userName,
            authProtocol,
            privProtocol,
        )
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

        # user: usr-md5-des, auth: MD5, priv DES, contextEngineId: 8000000001020304
        # this USM entry is used for TRAP receiving purposes

        # help(addV3User) returns ->
        # addV3User(snmpEngine, userName, authProtocol=(1, 3, 6, 1, 6, 3, 10, 1, 1, 1), authKey=None, privProtocol=(1, 3, 6, 1, 6, 3, 10, 1, 2, 1), priv    Key=None, securityEngineId=None, securityName=None, contextEngineId=None)

        if ctx_engine_id is not None:
            config.addV3User(
                _snmp_engine,
                userName,
                authProtocol,
                authKey,
                privProtocol,
                privKey,
                contextEngineId=v2c.OctetString(hexValue=ctx_engine_id),
            )
        else:
            config.addV3User(_snmp_engine, userName, authProtocol, authKey, privProtocol, privKey)

    return _py_config, _snmp_engine
