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
snmptrapd is responsible for SNMP trap receipt and publishing activities.
It's behavior is controlled by CBS (config binding service) using a
JSON construct obtained via a "get_config" call or (for testing/standalone
purposes) a file specified using the env variable "CBS_SIM_JSON".

As traps arrive they are decomposed and transformed into a JSON message which
is published to a dmaap instance that has been defined by controller.

:Parameters:
    usage:  snmptrapd.py [-v]
:Keywords:
    onap dcae snmp trap publish dmaap
"""

__docformat__ = "restructuredtext"

# basics
import argparse
import array
import asyncio
from collections import Counter
import datetime
import errno
import inspect
import json
import logging
import logging.handlers
import os
import pprint
import requests
import re
import sys
import signal
import string
import socket
import time
import traceback
import unicodedata
import uuid as uuid_mod

# pysnmp
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp, udp6

# from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
from pysnmp import debug

# snmptrap
import trapd_settings as tds

from trapd_runtime_pid import save_pid, rm_pid
from trapd_get_cbs_config import get_cbs_config
from trapd_exit import cleanup_and_exit
from trapd_http_session import init_session_obj, close_session_obj, reset_session_obj
from trapd_snmpv3 import load_snmpv3_credentials
from trapd_vb_types import pysnmp_to_netsnmp_varbind_convert
from trapd_io import roll_all_logs, open_eelf_logs, roll_file, open_file, close_file, ecomp_logger, stdout_logger

import trapd_stormwatch_settings as sws
import trapd_stormwatch as stormwatch

import trapd_stats_settings as stats

prog_name = os.path.basename(__file__)
verbose = False

# # # # # # # # # # #
# fx: usage_err
# # # # # # # # # # #


def usage_err():
    """
    Notify of incorrect (argument) usage
    :Parameters:
       none
    :Exceptions:
       none
    :Keywords:
       usage args
    """

    print("Incorrect usage invoked.  Correct usage:")
    print("  %s [-v]" % prog_name)
    cleanup_and_exit(1, "undefined")


# # # # # # # # # # # # # # # # # # #
# fx: load_all_configs
# # # # # # # # # # ## # # # # # # #


def load_all_configs(_signum, _frame):
    """
    Calls individual functions to read various config files required.  This
    function is called directly (e.g. at startup) and is also registered
    with signal handling (e.g. kill -sigusr1 <pid>)

    :Parameters:
      signum and frame (only present when called via signal to running process)
    :Exceptions:
      none
    :Keywords:
      config files
    :Variables:
      yaml_conf_file
      rs
    """

    if int(_signum) != 0:
        msg = "received signal %s at frame %s; re-reading configs" % (_signum, _frame)
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    # re-request config from broker:
    if not get_cbs_config():
        msg = "Error (re)loading CBS config - FATAL ERROR, exiting"
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)
    else:
        current_runtime_config_file_name = tds.c_config["files"]["runtime_base_dir"] + "/tmp/current_config.json"
        if int(_signum) != 0:
            msg = "updated config logged to : %s" % current_runtime_config_file_name
        else:
            msg = "current config logged to : %s" % current_runtime_config_file_name
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    with open(current_runtime_config_file_name, "w") as outfile:
        json.dump(tds.c_config, outfile)

    # reset http session based on latest config
    tds.http_requ_session = reset_session_obj(tds.http_requ_session)

    # reload sw participating entries, reset counter dictionary
    traps_configured = stormwatch.sw_load_trap_config(tds.c_config)
    msg = "encountered %d trap configurations in CBS/json config" % traps_configured
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    tds.last_minute = datetime.datetime.now().minute
    tds.last_hour = datetime.datetime.now().hour
    tds.last_day = datetime.datetime.now().day

    # if here, configs re-read successfully
    return True


# # # # # # # # # # # # #
# fx: resolve_ip
# # # # # # # # # # # # #
def resolve_ip(_loc_ip_addr_str):

    try:

        if int(tds.dns_cache_ip_expires[_loc_ip_addr_str] < int(time.time())):
            raise Exception(
                "cache expired for %s at %d - updating value"
                % (_loc_ip_addr_str, (tds.dns_cache_ip_expires[_loc_ip_addr_str]))
            )
        else:
            agent_fqdn = tds.dns_cache_ip_to_name[_loc_ip_addr_str]

    except Exception as e:
        msg = "dns cache expired or missing for %s - refreshing" % _loc_ip_addr_str
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        try:
            agent_fqdn, alias, addresslist = socket.gethostbyaddr(_loc_ip_addr_str)
        except Exception as e:
            agent_fqdn = _loc_ip_addr_str

        tds.dns_cache_ip_to_name[_loc_ip_addr_str] = agent_fqdn
        tds.dns_cache_ip_expires[_loc_ip_addr_str] = time.time() + int(tds.c_config["cache"]["dns_cache_ttl_seconds"])
        msg = "cache for %s (%s) updated - set to expire at %d" % (
            agent_fqdn,
            _loc_ip_addr_str,
            tds.dns_cache_ip_expires[_loc_ip_addr_str],
        )
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    return agent_fqdn


# # # # # # # # # # # # #
# fx: log_all_arriving_traps
# # # # # # # # # # # # #


def log_all_arriving_traps():

    # roll logs as needed/defined in files.roll_frequency
    if tds.c_config["files"]["roll_frequency"] == "minute":
        curr_minute = datetime.datetime.now().minute
        if curr_minute != tds.last_minute:
            roll_all_logs()
            tds.last_minute = curr_minute
    elif tds.c_config["files"]["roll_frequency"] == "hour":
        curr_hour = datetime.datetime.now().hour
        if curr_hour != tds.last_hour:
            roll_all_logs()
            tds.last_hour = curr_hour
    else:
        # otherwise, assume daily roll
        curr_day = datetime.datetime.now().day
        if curr_day != tds.last_day:
            roll_all_logs()
            tds.last_day = curr_day

    # always log arriving trap
    try:
        time_now = int(round(time.time(), 0))
        arrived_epoch_time_int = int(tds.trap_dict["time received"])
        tds.arriving_traps_fd.write(
            "%d %s; %s %s %s %s %s %s %s %s %s %s %s %s %s\n"
            % (
                time_now,
                datetime.datetime.fromtimestamp(time_now).strftime("%a %b %d %H:%M:%S %Y"),
                tds.trap_dict["time received"],
                datetime.datetime.fromtimestamp(arrived_epoch_time_int).strftime("%a %b %d %H:%M:%S %Y"),
                tds.trap_dict["trap category"],
                tds.trap_dict["epoch_serno"],
                tds.trap_dict["notify OID"],
                tds.trap_dict["agent name"],
                tds.trap_dict["agent address"],
                tds.trap_dict["pdu agent name"],
                tds.trap_dict["pdu agent address"],
                tds.trap_dict["cambria.partition"],
                tds.trap_dict["protocol version"],
                tds.trap_dict["uuid"],
                tds.all_vb_str,
            )
        )

    except Exception as e:
        msg = "Error writing to %s : %s - arriving trap %s NOT LOGGED" % (
            tds.arriving_traps_filename,
            str(e),
            tds.trap_dict["uuid"],
        )
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_ERROR, tds.CODE_GENERAL, msg)


# # # # # # # # # # # # #
# fx: log_published_messages
# # # # # # # # # # # # #


def log_published_messages(_post_data_enclosed):

    # FMDL: should keep data dictionary of Fd's open, and reference those vs.
    #        repeatedly opening append-mode

    msg = "adding trap UUID %s to json log" % tds.trap_dict["uuid"]
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    try:
        tds.json_traps_fd.write("%s\n" % _post_data_enclosed)
        msg = "successfully logged json for %s to %s" % (tds.trap_dict["uuid"], tds.json_traps_filename)
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
    except Exception as e:
        msg = "Error writing to %s : %s - trap %s NOT LOGGED" % (tds.json_traps_filename, str(e), tds.trap_dict["uuid"])
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_ERROR, tds.CODE_GENERAL, msg)


# # # # # # # # # # # # #
# fx: post_dmaap
# # # # # # # # # # # # #


def post_dmaap():
    """
    Publish trap daata in json format to dmaap
    :Parameters:
    :Exceptions:
      none
    :Keywords:
      http post dmaap json message
    :Variables:
    """

    http_headers = {"Content-type": "application/json"}

    if tds.http_requ_session is None:
        msg = "tds.http_requ_session is None - getting new (%s)" % tds.http_requ_session
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        tds.http_requ_session = init_session_obj()

    # if only 1 trap, ship as-is
    if tds.traps_since_last_publish == 1:
        post_data_enclosed = tds.all_traps_json_str
    else:
        # otherwise, add brackets around package
        post_data_enclosed = "[" + tds.all_traps_json_str + "]"

    msg = "post_data_enclosed: %s" % (post_data_enclosed)
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    k = 0
    dmaap_pub_success = False

    while not dmaap_pub_success and k < (int(tds.c_config["publisher"]["http_retries"])):
        try:
            if (
                tds.c_config["streams_publishes"]["sec_fault_unsecure"]["aaf_username"] == ""
                or tds.c_config["streams_publishes"]["sec_fault_unsecure"]["aaf_username"] is None
            ):
                msg = "%d trap(s) : %s - attempt %d (unsecure)" % (
                    tds.traps_since_last_publish,
                    tds.trap_uuids_in_buffer,
                    k,
                )
                ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
                http_resp = tds.http_requ_session.post(
                    tds.c_config["streams_publishes"]["sec_fault_unsecure"]["dmaap_info"]["topic_url"],
                    post_data_enclosed,
                    headers=http_headers,
                    timeout=tds.timeout_seconds,
                )
            else:
                msg = "%d trap(s) : %s - attempt %d (secure)" % (
                    tds.traps_since_last_publish,
                    tds.trap_uuids_in_buffer,
                    k,
                )
                ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
                http_resp = tds.http_requ_session.post(
                    tds.c_config["streams_publishes"]["sec_fault_unsecure"]["dmaap_info"]["topic_url"],
                    post_data_enclosed,
                    auth=(
                        tds.c_config["streams_publishes"]["sec_fault_unsecure"]["aaf_username"],
                        tds.c_config["streams_publishes"]["sec_fault_unsecure"]["aaf_password"],
                    ),
                    headers=http_headers,
                    timeout=tds.timeout_seconds,
                )

            if http_resp.status_code == requests.codes.ok:
                msg = "%d trap(s) successfully published: %s" % (tds.traps_since_last_publish, tds.trap_uuids_in_buffer)
                ecomp_logger(tds.LOG_TYPE_METRICS, tds.SEV_INFO, tds.CODE_GENERAL, msg)
                log_published_messages(post_data_enclosed)
                tds.last_pub_time = time.time()
                dmaap_pub_success = True
                break
            else:
                msg = "Trap(s) %s publish attempt %d returned non-normal: %d %s" % (
                    tds.trap_uuids_in_buffer,
                    k,
                    http_resp.status_code,
                    http_resp.text,
                )
                ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)

        except OSError as e:
            msg = "OS exception while attempting to post %s attempt %d: (%s) %s %s" % (
                tds.trap_uuids_in_buffer,
                k,
                e.errno,
                e.strerror,
                str(e),
            )
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)

        except requests.exceptions.RequestException as e:
            msg = "Requests exception while attempting to post %s attempt %d: (%d) %s" % (
                tds.trap_uuids_in_buffer,
                int(k),
                int(e.errno),
                str(e.strerror),
            )
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)

        k += 1

        if k < int(tds.c_config["publisher"]["http_retries"]):
            msg = "sleeping %.4f seconds and retrying" % (tds.seconds_between_retries)
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)
            time.sleep(tds.seconds_between_retries)
        else:
            break

    if not dmaap_pub_success:
        msg = "ALL publish attempts failed for traps %s to URL %s " % (
            tds.trap_uuids_in_buffer,
            tds.c_config["streams_publishes"]["sec_fault_unsecure"]["dmaap_info"]["topic_url"],
        )
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_ERROR, tds.CODE_GENERAL, msg)

    # FMDL: This currently tries, then logs error and trashes buffer if all dmaap attempts fail. Better way?
    tds.traps_since_last_publish = 0
    tds.trap_uuids_in_buffer = ""
    tds.all_traps_json_str = ""
    tds.first_trap = True


# # # # # # # # # # # # # # # # # # #
# fx: request_observer for community string rewrite
# # # # # # # # # # # # # # # # # # #


def comm_string_rewrite_observer(snmpEngine, execpoint, variables, cbCtx):

    # match ALL community strings
    if re.match(".*", str(variables["communityName"])):
        variables["communityName"] = variables["communityName"].clone("public")


# # # # # # # # # # # # # # # # # # #
# fx: snmp_engine_observer_cb
#     callback for when trap is received
# # # # # # # # # # # # # # # # # # #


def snmp_engine_observer_cb(snmp_engine, execpoint, variables, cbCtx):
    """
    Decompose trap attributes and load in dictionary which is later used to
    create json string for publishing to dmaap.
    :Parameters:
      snmp_engine
         snmp engine created to listen for arriving traps
      execpoint
         point in code that snmp_engine_observer_cb was invoked
      variables
         trap attributes
      cbCtx
         callback context
    :Exceptions:
      none
    :Keywords:
      UEB non-AAF legacy http post
    :Variables:
    """

    # All sorts of goodies available:
    # print('Execution point: %s' % execpoint)
    # print('* transportDomain: %s' % '.'.join([str(x) for x in variables['transportDomain']]))
    # print('* transportAddress: %s' % '@'.join([str(x) for x in variables['transportAddress']]))
    # print('* securityModel: %s' % variables['securityModel'])
    # print('* securityName: %s' % variables['securityName'])
    # print('* securityLevel: %s' % variables['securityLevel'])
    # print('* contextEngineId: %s' % variables['contextEngineId'].prettyPrint())
    # print('* contextName: %s' % variables['contextName'].prettyPrint())
    # print('* PDU: %s' % variables['pdu'].prettyPrint())
    # V1 only:
    # print('* enterprise: %s' % variables['pdu']['enterprise'].prettyPrint())
    # V1 name (e.g. coldstart, warmstart):
    # print('* generic: %s' % variables['pdu']['generic-trap'].prettyPrint())
    # print('* generic: %d' % variables['pdu']['generic-trap'])
    # print('* specific: %s' % variables['pdu']['specific-trap'].prettyPrint())
    # print('* specific: %d' % variables['pdu']['specific-trap'])

    # init dictionary on new trap
    tds.trap_dict = {}

    # FMDL.CHECK_WITH_DOWNSTREAM_CONSUMERS: get rid of round for millisecond val
    # epoch_second = int(round(time.time()))
    epoch_msecond = time.time()
    epoch_second = int(round(epoch_msecond))
    if epoch_second == tds.last_epoch_second:
        tds.traps_in_epoch += 1
    else:
        tds.traps_in_epoch = 0
    tds.last_epoch_second = epoch_second
    traps_in_epoch_04d = format(tds.traps_in_epoch, "04d")
    tds.trap_dict["epoch_arrived"] = epoch_second
    tds.trap_dict["epoch_serno"] = int((str(epoch_second) + str(traps_in_epoch_04d)))

    # assign uuid to trap
    tds.trap_dict["uuid"] = str(uuid_mod.uuid1())

    # ip and hostname
    ip_addr_str = str(variables["transportAddress"][0])
    # set agent address and name to source of packet, OVERWRITE if
    # .1.3.6.1.6.3.18.1.3.0 varbind encountered later in trap processing
    tds.trap_dict["agent address"] = ip_addr_str
    tds.trap_dict["agent name"] = resolve_ip(ip_addr_str)
    # set overridden/logical address and name to source of packet so we know
    # original value if .1.3.6.1.6.3.18.1.3.0 shows up
    # NOTE:  This does NOT change ever, label may change to
    #        "overridden agent..." in the future for truth in nameing
    tds.trap_dict["pdu agent address"] = tds.trap_dict["agent address"]
    tds.trap_dict["pdu agent name"] = tds.trap_dict["agent name"]

    # log arrival now that we have agent addr
    msg = "trap from %s %s, assigned uuid: %s" % (ip_addr_str, tds.trap_dict["agent name"], tds.trap_dict["uuid"])
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    tds.trap_dict["cambria.partition"] = str(tds.trap_dict["agent name"])
    # do not include cleartext community in pub
    tds.trap_dict["community"] = ""
    tds.trap_dict["community len"] = 0

    snmp_version = variables["securityModel"]
    if snmp_version == 1:
        tds.trap_dict["protocol version"] = "v1"
        # enterprise = variables['pdu']['enterprise'].prettyPrint()
        # generic_trap = variables['pdu']['generic-trap']
        # specific_trap = variables['pdu']['specific-trap']
        # if generic_trap < 6:
        #     tds.trap_dict["notify OID"] = "." + str(enterprise) + "." + str(specific_trap)
        # else:
        #     tds.trap_dict["notify OID"] = "." + str(enterprise) + ".0." + str(specific_trap)
        # tds.trap_dict["notify OID len"] = tds.trap_dict["notify OID"].count('.')
        # tds.trap_dict["sysUptime"] = variables['pdu']['time-stamp'].prettyPrint()

    elif snmp_version == 2:
        tds.trap_dict["protocol version"] = "v2c"

    elif snmp_version == 3:
        tds.trap_dict["protocol version"] = "v3"
        # tds.trap_dict["security level"] = str(variables['securityLevel'])
        # tds.trap_dict["context name"] = str(
        #     variables['contextName'].prettyPrint())
        # tds.trap_dict["security name"] = str(variables['securityName'])
        # tds.trap_dict["security engine"] = str(
        #     variables['contextEngineId'].prettyPrint())

    else:
        tds.trap_dict["protocol version"] = "unknown"

    # tds.trap_dict['time received'] = epoch_msecond
    tds.trap_dict["time received"] = epoch_second
    tds.trap_dict["trap category"] = (
        tds.c_config["streams_publishes"]["sec_fault_unsecure"]["dmaap_info"]["topic_url"]
    ).split("/")[-1]

    return True


# # # # # # # # # # # # # # # # # # #
# fx: request_observer for community string rewrite
# # # # # # # # # # # # # # # # # # #


def add_varbind_to_log_string(vb_idx, vb_oid, vb_type, vb_val):
    """
    Called for each varbind, adds individual attributes of varbind instance to
    all_vb_str for logging.
    :Parameters:
      vb_idx
        index to specific varbind being processed
      vb_oid
        the varbind oid
      vb_type
        the varbind type
      vb_val
        the value of the varbind
    :Exceptions:
      none
    :Keywords:
      varbind extract log
    :Variables:
    """

    if vb_idx == 0:
        tds.all_vb_str = "varbinds:"

    tds.all_vb_str = (
        tds.all_vb_str + " [" + str(vb_idx) + "] " + str(vb_oid) + " {" + vb_type + "} " + str(vb_val.prettyPrint())
    )

    # try:
    #     tds.all_vb_str = tds.all_vb_str + " [" + str(vb_idx) + "] " + vb_oid + " {" + vb_type + "} " + vb_val
    #     return 0
    # except Exception as e:
    #     msg = "unable to add varbind to log string: %s" % (str(e))
    #     stdout_logger(msg)
    #     ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)
    #     return 1


def add_varbind_to_json(vb_idx, vb_oid, vb_type, vb_val):
    """
    Called for each varbind, adds individual attributes of varbind instance to
    vb_json_str.  vb_json_str will be added to curr_trap_json_str prior to publish.
    :Parameters:
      vb_idx
        index to specific varbind being processed
      vb_oid
        the varbind oid
      vb_val
        the value of the varbind
    :Exceptions:
      none
    :Keywords:
      varbind extract json
    :Variables:
    """

    agent_override_oid = ".1.3.6.1.6.3.18.1.3.0"
    _individual_vb_dict = {}

    # if first varbind (sysUptime), always return immediately as
    # we don't publish sysUptime
    if vb_idx == 0:
        return 0

    _vb_oid = "." + str(vb_oid.prettyPrint())
    _vb_value = vb_val.prettyPrint()
    _vb_type = pysnmp_to_netsnmp_varbind_convert(vb_type)

    # if second varbind, use as notifyOID for all snmp versions
    if vb_idx == 1:
        tds.trap_dict["notify OID"] = "." + _vb_value
        tds.trap_dict["notify OID len"] = tds.trap_dict["notify OID"].count(".")
        return 0

    # if override varbind OID, use value as agent address
    if _vb_oid == agent_override_oid:
        tds.trap_dict["agent address"] = _vb_value
        tds.trap_dict["agent name"] = resolve_ip(_vb_value)
        return 0

    # for SNMPv1 traps, skip varbinds 2, 3 and 4:
    #    - .1.3.6.1.6.3.18.1.3.0 agent override
    #    - .1.3.6.1.6.3.18.1.4.0 community string
    #    - .1.3.6.1.6.3.1.1.4.3.0 V1 enterprise in original trap
    if tds.trap_dict["protocol version"] == "v1":
        if vb_idx < 5:
            return 0

    if tds.first_varbind:
        tds.all_vb_json_str = ', "varbinds": ['
        tds.first_varbind = False
    else:
        tds.all_vb_json_str = tds.all_vb_json_str + " ,"

    _individual_vb_dict.clear()
    _individual_vb_dict["varbind_oid"] = _vb_oid
    _individual_vb_dict["varbind_type"] = _vb_type
    _individual_vb_dict["varbind_value"] = _vb_value

    _individual_vb_json_str = json.dumps(_individual_vb_dict)

    tds.all_vb_json_str = tds.all_vb_json_str + _individual_vb_json_str
    return 1


# Callback function for receiving notifications
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def notif_receiver_cb(snmp_engine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    """
    Callback executed when trap arrives
    :Parameters:
      snmp_engine
        snmp engine created to listen for arriving traps
      stateReference
      contextEngineId
      contextName
      varBinds
        trap varbinds - why we are here
      cbCtx
        callback context
    :Exceptions:
      none
    :Keywords:
      callback trap arrival
    :Variables:
    """
    msg = "processing varbinds for %s" % (tds.trap_dict["uuid"])
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    # FMDL update reset location when batching publishes
    pdu_varbind_count = 0
    payload_varbinds = 0
    tds.all_vb_json_str = ""
    tds.all_vb_str = " varbinds:"
    tds.first_varbind = True

    # iterate over varbinds, add to json struct
    for vb_oid, vb_val in varBinds:
        log_ret = add_varbind_to_log_string(pdu_varbind_count, vb_oid, vb_val.__class__.__name__, vb_val)
        varbinds_added = add_varbind_to_json(pdu_varbind_count, vb_oid, vb_val.__class__.__name__, vb_val)
        payload_varbinds += varbinds_added
        pdu_varbind_count += 1

    curr_trap_json_str = json.dumps(tds.trap_dict)
    # now have everything except varbinds in "curr_trap_json_str"

    # if varbinds present - which will almost always be the case - add all_vb_json_str to trap_json_message
    if payload_varbinds != 0:
        # close out vb array
        tds.all_vb_json_str = tds.all_vb_json_str + "]"

        # remove last close bracket from curr_trap_json_str
        curr_trap_json_str = curr_trap_json_str[:-1]

        # add vb_json_str to payload
        curr_trap_json_str = curr_trap_json_str + tds.all_vb_json_str

        # add last close brace back in
        curr_trap_json_str = curr_trap_json_str + "}"

    msg = "trap %s : %s" % (tds.trap_dict["uuid"], curr_trap_json_str)
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    # always log arriving traps
    log_all_arriving_traps()

    # now have a complete json message for this trap in "curr_trap_json_str"
    tds.traps_since_last_publish += 1
    milliseconds_since_last_publish = (time.time() - tds.last_pub_time) * 1000

    # only add to publish buffer if stormwatch is NOT active
    if stormwatch.sw_storm_active(tds.trap_dict["agent address"], tds.trap_dict["notify OID"]):
        msg = "stormwatch active - deflecting notification %s from %s" % (
            tds.trap_dict["notify OID"],
            tds.trap_dict["agent address"],
        )
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
    else:
        msg = "adding %s to buffer" % (tds.trap_dict["uuid"])
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        if tds.first_trap:
            tds.all_traps_json_str = curr_trap_json_str
            tds.trap_uuids_in_buffer = tds.trap_dict["uuid"]

            tds.first_trap = False
        else:
            tds.trap_uuids_in_buffer = tds.trap_uuids_in_buffer + ", " + tds.trap_dict["uuid"]
            tds.all_traps_json_str = tds.all_traps_json_str + ", " + curr_trap_json_str

    if tds.traps_since_last_publish >= int(tds.c_config["publisher"]["max_traps_between_publishes"]):
        msg = "num traps since last publish (%d) exceeds threshold (%d) - publish traps" % (
            tds.traps_since_last_publish,
            int(tds.c_config["publisher"]["max_traps_between_publishes"]),
        )
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        post_dmaap()
    elif milliseconds_since_last_publish >= int(tds.c_config["publisher"]["max_milliseconds_between_publishes"]):
        msg = (
            "num milliseconds since last publish (%.0f) exceeds threshold - publish traps"
            % milliseconds_since_last_publish
        )
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        post_dmaap()
    else:
        msg = (
            "neither milliseconds_since_last_publish (%.0f) or traps_since_last_publish (%d) exceed threshold - continue"
            % (milliseconds_since_last_publish, tds.traps_since_last_publish)
        )
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)


# # # # # # # # # # # # #
# Main  MAIN  Main  MAIN
# # # # # # # # # # # # #
# parse command line args

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Post SNMP traps " "to message bus")
    parser.add_argument("-v", action="store_true", dest="verbose", help="verbose logging")
    parser.add_argument("-?", action="store_true", dest="usage_requested", help="show command line use")

    # parse args
    args = parser.parse_args()

    # set vars from args
    verbose = args.verbose
    usage_requested = args.usage_requested

    # if usage, just display and exit
    if usage_requested:
        usage_err()

    # init vars
    tds.init()
    sws.init()
    stats.init()

    # FMDL: add with stormWatch
    # init sw vars
    stormwatch.sw_init()

    # Set initial startup hour for rolling logfile
    tds.last_hour = datetime.datetime.now().hour

    # get config binding service (CBS) values (either broker, or json file override)
    load_all_configs(0, 0)
    msg = "%s : %s version %s starting" % (
        prog_name,
        tds.c_config["snmptrapd"]["title"],
        tds.c_config["snmptrapd"]["version"],
    )
    stdout_logger(msg)

    # open various ecomp logs
    open_eelf_logs()

    # bump up logging level if overridden at command line
    if verbose:
        msg = "WARNING:  '-v' argument present.  All diagnostic messages will be logged.  This can slow things down, use only when needed."
        tds.minimum_severity_to_log = 0
        stdout_logger(msg)
        # use specific flags or 'all' for full debugging
        # debug.setLogger(debug.Debug('dsp', 'msgproc'))
        debug.setLogger(debug.Debug("all"))

    # name and open arriving trap log
    tds.arriving_traps_filename = (
        tds.c_config["files"]["runtime_base_dir"]
        + "/"
        + tds.c_config["files"]["log_dir"]
        + "/"
        + (tds.c_config["files"]["arriving_traps_log"])
    )
    tds.arriving_traps_fd = open_file(tds.arriving_traps_filename)
    msg = "arriving traps logged to: %s" % tds.arriving_traps_filename
    stdout_logger(msg)
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    # name and open json trap log
    tds.json_traps_filename = (
        tds.c_config["files"]["runtime_base_dir"]
        + "/"
        + tds.c_config["files"]["log_dir"]
        + "/"
        + "DMAAP_"
        + (tds.c_config["streams_publishes"]["sec_fault_unsecure"]["dmaap_info"]["topic_url"].split("/")[-1])
        + ".json"
    )
    tds.json_traps_fd = open_file(tds.json_traps_filename)
    msg = "published traps logged to: %s" % tds.json_traps_filename
    stdout_logger(msg)
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    # setup signal handling for config reload
    signal.signal(signal.SIGUSR1, load_all_configs)

    # save current PID for future/external reference
    tds.pid_file_name = (
        tds.c_config["files"]["runtime_base_dir"] + "/" + tds.c_config["files"]["pid_dir"] + "/" + prog_name + ".pid"
    )
    msg = "Runtime PID file: %s" % tds.pid_file_name
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
    rc = save_pid(tds.pid_file_name)

    # Get the event loop for this thread
    loop = asyncio.get_event_loop()

    # Create SNMP engine with autogenerated engineID pre-bound
    # to socket transport dispatcher
    snmp_engine = engine.SnmpEngine()

    # # # # # # # # # # # #
    # Transport setup
    # # # # # # # # # # # #

    # UDP over IPv4
    try:
        ipv4_interface = tds.c_config["protocols"]["ipv4_interface"]
        ipv4_port = int(tds.c_config["protocols"]["ipv4_port"])

        try:
            # FIXME:  this doesn't appear to throw an exception even if
            #         the userID is unable (perms) to bind to port
            #
            #         We may need to open raw port using other
            #         means to confirm proper privileges (then
            #         close it and reopen w/ pysnmp api)
            config.addTransport(
                snmp_engine, udp.domainName + (1,), udp.UdpTransport().openServerMode((ipv4_interface, ipv4_port))
            )
        except Exception as e:
            msg = "Unable to bind to %s:%d - %s" % (ipv4_interface, ipv4_port, str(e))
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_FATAL, tds.CODE_GENERAL, msg)
            stdout_logger(msg)
            cleanup_and_exit(1, tds.pid_file_name)

    except Exception as e:
        msg = "IPv4 interface and/or port not specified in config - not listening for IPv4 traps"
        stdout_logger(msg)
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)

    # UDP over IPv6
    try:
        ipv6_interface = tds.c_config["protocols"]["ipv6_interface"]
        ipv6_port = int(tds.c_config["protocols"]["ipv6_port"])

        try:
            config.addTransport(
                snmp_engine, udp6.domainName, udp6.Udp6Transport().openServerMode((ipv6_interface, ipv6_port))
            )
        except Exception as e:
            msg = "Unable to bind to %s:%d - %s" % (ipv6_interface, ipv6_port, str(e))
            stdout_logger(msg)
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_FATAL, tds.CODE_GENERAL, msg)
            cleanup_and_exit(1, tds.pid_file_name)

    except Exception as e:
        msg = "IPv6 interface and/or port not specified in config - not listening for IPv6 traps"
        stdout_logger(msg)
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)

    # # # # # # # # # # # #
    # SNMPv1/2c setup
    # # # # # # # # # # # #

    # SecurityName <-> CommunityName mapping
    #     to restrict trap reception to only those with specific community
    #     strings
    config.addV1System(snmp_engine, "my-area", "public")

    # register comm_string_rewrite_observer for message arrival
    snmp_engine.observer.registerObserver(comm_string_rewrite_observer, "rfc2576.processIncomingMsg:writable")

    # # # # # # # # # # # #
    # SNMPv3 setup
    # # # # # # # # # # # #
    config, snmp_engine = load_snmpv3_credentials(config, snmp_engine, tds.c_config)

    # register snmp_engine_observer_cb for message arrival
    snmp_engine.observer.registerObserver(
        snmp_engine_observer_cb,
        "rfc3412.receiveMessage:request",
        "rfc3412.returnResponsePdu",
    )

    # Register SNMP Application at the SNMP engine
    ntfrcv.NotificationReceiver(snmp_engine, notif_receiver_cb)

    snmp_engine.transportDispatcher.jobStarted(1)  # loop forever

    # Run I/O dispatcher which will receive traps
    try:
        snmp_engine.transportDispatcher.runDispatcher()
    except Exception as e:
        snmp_engine.observer.unregisterObserver()
        snmp_engine.transportDispatcher.closeDispatcher()
        cleanup_and_exit(1, tds.pid_file_name)
