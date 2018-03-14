# ============LICENSE_START=======================================================)
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
dcae_snmptrapd is responsible for SNMP trap receipt and publishing activities.
It's behavior is controlled by CBS (config binding service) using a
JSON construct obtained via a "get_config" call or (for testing/standalone
purposes) a file specified using the env variable "CBS_SIM_JSON".

As traps arrive they are decomposed and transformed into a JSON message which
is published to a dmaap instance that has been defined by controller.

:Parameters:
    usage:  dcae_snmptrapd.py -c <yaml_conf_file_name> [-v]
:Keywords:
    onap dcae snmp trap publish dmaap
"""

__docformat__ = 'restructuredtext'

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

# dcae_snmptrap
from trapd_runtime_pid import save_pid, rm_pid
from trapd_get_cbs_config import trapd_get_cbs_config
from trapd_exit import cleanup_and_exit
from trapd_http_session import init_session_obj

from trapd_logging import eelf_log_open, ecomp_logger, stdout_logger
from trapd_logging import eelf_error_fd, eelf_debug_fd, eelf_audit_fd, \
                          eelf_metrics_fd, current_min_sev_log_level

prog_name = os.path.basename(__file__)

traps_in_minute = 0
last_epoch_second = 0
traps_since_last_publish = 0
last_pub_time = 0
milliseconds_since_last_publish = 0

# consul config dict
c_config = {}

# Requests session object
rs = None

# <DNS cache>
#
#     dns_cache_ip_to_name
#        key [ip address] -> fqdn
#     dns_cache_ip_expires
#        key [ip address] -> epoch time this entry expires and must be reloaded
dns_cache_ip_to_name = {}
dns_cache_ip_expires = {}
# </DNS cache>

# <trap config>
trap_conf_dict = {}
# </trap config>

pid_file_name = ""

# logging types
LOG_TYPES = ["none", "ERROR", "DEBUG", "AUDIT", "METRICS"]
LOG_TYPE_NONE = 0
LOG_TYPE_ERROR = 1
LOG_TYPE_DEBUG = 2
LOG_TYPE_AUDIT = 3
LOG_TYPE_METRICS = 4

# sev types
SEV_TYPES = ["none", "DETAILED", "INFO", "WARN", "CRITICAL", "FATAL"]
SEV_NONE = 0
SEV_DETAILED = 1
SEV_INFO = 2
SEV_WARN = 3
SEV_CRIT = 4
SEV_FATAL = 5

CODE_GENERAL="100"

undefined = "undefined"
usage_requested = False
first_varbind = True
first_trap = True
last_pub_time = time.time()
traps_since_last_publish = 0

eelf_error_fd = None
eelf_debug_fd = None
eelf_audit_fd = None
eelf_metrics_fd = None

json_fd = None
json_log_filename=""
last_hour = -1

verbose = False

trap_dict = {}
individual_vb_dict = {}
all_vb_json_str = ""
all_traps_str = ""
trap_uuids_in_buffer = ""

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

    print('Incorrect usage invoked.  Correct usage:')
    print('  %s [-v]' % prog_name)
    cleanup_and_exit(1, "undefined")


# # # # # # # # # # # # # # # # # # #
# fx: load_all_configs
# FIXME:  currently on hold for load and signal handling convergence
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

    global c_config, rs

    if int(_signum) != 0:
        msg = ("received signal %s at frame %s; re-reading configs"
                         % (_signum, _frame))
        ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    # Initialize dmaap requests session object. Close existing session
    # if applicable.
    if rs is not None:
        rs.close()
    rs = init_session_obj()

    # re-request config from config binding service 
    # (either broker, or json file override)
    c_config = trapd_get_cbs_config()

# # # # # # # # # # # # #
# fx: rename_json_log
# # # # # # # # # # # # #


def rename_json_log(_outputFname):
    """
    Renames JSON output file to include ISO-formatted date suffix
    :Parameters:
      signum and frame (only present when called via signal to running process)
    :Exceptions:
      none
    :Keywords:
      json log
    :Variables:
      json log filename
    """

    global json_fd

    # check if outputfile exists; if it does, move to timestamped version
    _outputFnameBak = "%s.%s" % (_outputFname,
                                 datetime.datetime.fromtimestamp(time.time()).
                                 fromtimestamp(time.time()).
                                 strftime('%Y-%m-%dT%H:%M:%S'))

    # close existing file
    close_json_log()

    if os.path.isfile(_outputFname):
        dcae_logger.debug('Renaming %s to %s' %
                          (_outputFname, _outputFnameBak))
        try:
            os.rename(_outputFname, _outputFnameBak)
        except Exception as e:
            msg = ("Unable to move %s to %s - %s" % (_outputFname, _outputFnameBak, str(e)))
            ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    # open new (empty) log file
    try:
        json_fd = open_json_log()
        return True
    except Exception as e:
        msg = ("Error opening new json log file %s : %s - EXITING" % (_outputFname, str(e)))
        ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_FATAL, CODE_GENERAL, msg)
        stdout_logger(msg)
        sys.exit(1)

# # # # # # # # # # # # #
# fx: open_json_log
# # # # # # # # # # # # #


def open_json_log():

    global json_log_filename

    try:
        # open append mode just in case so nothing is lost, but should be
        # non-existent file
        _json_fd = open(json_log_filename, 'a')
        msg = "Opened " + json_log_filename + " append mode"
        ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
        return _json_fd
    except Exception as e:
        msg = "Error opening " + json_log_filename + " append mode - " + str(e)
        ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_FATAL, CODE_GENERAL, msg)
        sys.exit(1)


# # # # # # # # # # # # #
# fx: close_json_log
# # # # # # # # # # # # #


def close_json_log():

    global json_fd

    try:
        json_fd.close()
    except Exception as e:
        msg = "Error closing %s : %s - results indeterminate" % (json_log_filename, str(e))
        ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_FATAL, CODE_GENERAL, msg)

# # # # # # # # # # # # #
# fx: log_published_messages
# # # # # # # # # # # # #


def log_published_messages(loc_post_data_enclosed):

    # FIXME: should keep data dictionary of Fd's open, and reference those vs.
    #        repeatedly opening append-mode
    # open json audit log file

    global json_fd, json_log_filename, last_hour

    msg = "adding trap UUID %s to json log" % trap_dict["uuid"]
    ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    # close output file, backup current and move new one into place on day change
    curr_hour = datetime.datetime.now().hour
    if curr_hour < last_hour:
        rename_json_log(json_log_filename)
        json_fd = open_json_log(json_log_filename)

    try:
        m = loc_post_data_enclosed + '\n'
        json_fd.write('%s' % str(m))
    except Exception as e:
        msg = "Error writing to %s : %s - trap %s NOT LOGGED" %(json_log_filename, str(e), trap_dict["uuid"])
        ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_CRIT, CODE_GENERAL, msg)

    last_hour = curr_hour
    msg = "successfully logged json for %s to %s" % (trap_dict["uuid"], json_log_filename)
    ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

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

    global c_config, rs, last_pub_time, trap_uuids_in_buffer, all_traps_str, traps_since_last_publish, first_trap

    http_headers = {"Content-type": "application/json"}

    if rs is None:
        msg = "rs is None - getting new (%s)" % rs
        ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
        rs = init_session_obj()

    # msg = "rs: %s" % rs
    # ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    msg = "all_traps_str: %s" % (all_traps_str)
    ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    if traps_since_last_publish == 1:
       post_data_enclosed = all_traps_str
    else:
       post_data_enclosed = '[' + all_traps_str + ']'

    # post_data_enclosed = json.dumps(all_traps_str)

    msg = "post_data_enclosed: %s" % (post_data_enclosed)
    ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    k = 0
    dmaap_pub_success = False

    # use latest timeout and retries settings
    timeout_seconds = c_config['publisher']['http_timeout_milliseconds'] / 1000.0
    seconds_between_retries = c_config['publisher']['http_milliseconds_between_retries'] / 1000.0

    while not dmaap_pub_success and k < (int(c_config['publisher']['http_retries'])):
        try:
            if c_config['streams_publishes']['sec_fault_unsecure']['aaf_username'] == "" or c_config['streams_publishes']['sec_fault_unsecure']['aaf_username'] == None:
                msg = "%d trap(s) : %s - attempt %d (unsecure)" % (traps_since_last_publish, trap_uuids_in_buffer, k)
                ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
                http_resp = rs.post(c_config['streams_publishes']['sec_fault_unsecure']['dmaap_info']['topic_url'], post_data_enclosed,
                                                        headers=http_headers,
                                                        timeout=timeout_seconds)
            else:
                msg = "%d trap(s) : %s - attempt %d (secure)" % (traps_since_last_publish, trap_uuids_in_buffer, k)
                ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
                http_resp = rs.post(c_config['streams_publishes']['sec_fault_unsecure']['dmaap_info']['topic_url'], post_data_enclosed,
                                                        auth=(c_config['streams_publishes']['sec_fault_unsecure']['aaf_username'],
                                                              c_config['streams_publishes']['sec_fault_unsecure']['aaf_password']),
                                                        headers=http_headers,
                                                        timeout=timeout_seconds)

            if http_resp.status_code == requests.codes.ok:
                # msg = "%d trap(s) : %s successfully published - response from %s: %d %s" % (traps_since_last_publish, trap_uuids_in_buffer, ((c_config['streams_publishes']['sec_fault_unsecure']['dmaap_info']['topic_url']).split('/')[2][:-5]) ,http_resp.status_code, http_resp.text)
                msg = "%d trap(s) : %s successfully published" % (traps_since_last_publish, trap_uuids_in_buffer)
                ecomp_logger(c_config, LOG_TYPE_METRICS, SEV_INFO, CODE_GENERAL, msg)
                log_published_messages(post_data_enclosed)
                last_pub_time = time.time()
                dmaap_pub_success = True
                break
            else:
                msg = "Trap(s) %s publish attempt %d returned non-normal: %d %s" % (trap_uuids_in_buffer, k, http_resp.status_code, http_resp.text)
                ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_WARN, CODE_GENERAL, msg)

        except OSError as e:
            msg = "OS exception while attempting to post %s attempt %s: (%s) %s %s" % (trap_uuids_in_buffer, k,  e.errno, e.strerror, str(e))
            ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_WARN, CODE_GENERAL, msg)

        except requests.exceptions.RequestException as e:
            msg = "Requests exception while attempting to post %s attempt %d: (%d) %s" % (trap_uuids_in_buffer, int(k),  int(e.errno), str(e.strerror))
            ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_WARN, CODE_GENERAL, msg)

        k += 1

        if k < c_config['publisher']['http_retries']:
            msg = "sleeping %.4f seconds and retrying" % (seconds_between_retries)
            ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
            time.sleep(seconds_between_retries)
        else:
            break

    if not dmaap_pub_success:
        msg = "ALL publish attempts failed for traps %s to URL %s "\
                   % (trap_uuids_in_buffer, c_config['streams_publishes']['sec_fault_unsecure']['dmaap_info']['topic_url'])
        ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_CRIT, CODE_GENERAL, msg)

    # FIXME: This currently tries, then logs error and trashes buffer if all dmaap attempts fail. Better way? 
    traps_since_last_publish = 0
    trap_uuids_in_buffer=""
    all_traps_str = ""
    first_trap = True

# # # # # # # # # # # # # # # # # # #
# fx: request_observer for community string rewrite
# # # # # # # # # # # # # # # # # # #
def comm_string_rewrite_observer(snmpEngine, execpoint, variables, cbCtx):

    # match ALL community strings
    if re.match('.*', str(variables['communityName'])):
        # msg = "Rewriting communityName '%s' from %s into 'public'"  % (variables['communityName'], ':'.join([str(x) for x in
        #                                                                variables['transportInformation'][1]]))
        # ecomp_logger(c_config, eelf_debug_fd, eelf_debug_fd, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
        variables['communityName'] = variables['communityName'].clone('public')

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

    global trap_dict, last_epoch_second, traps_in_epoch

    # init dictionary on new trap
    trap_dict = {}

    # assign uuid to trap
    trap_dict["uuid"] = str(uuid_mod.uuid1())

    # ip and hostname
    ip_addr_str = str(variables['transportAddress'][0])
    trap_dict["agent address"] = ip_addr_str

    msg = 'snmp trap arrived from %s, assigned uuid: %s' % \
              (ip_addr_str, trap_dict["uuid"])
    ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    try:
        if int(dns_cache_ip_expires[ip_addr_str] < int(time.time())):
            msg = "dns cache expired for %s - updating value" % ip_addr_str
            ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
            raise Exception('cache expired for %s at %d - updating value' %
                            (ip_addr_str, (dns_cache_ip_expires[ip_addr_str])))
        else:
            trap_dict["agent name"] = dns_cache_ip_to_name[ip_addr_str]
    except:
        msg = "dns cache expired or missing for %s - refreshing" % ip_addr_str
        ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
        try:
            agent_fqdn,alias,addresslist = socket.gethostbyaddr(ip_addr_str)
        except:
            agent_fqdn = ip_addr_str

        trap_dict["agent name"] = agent_fqdn

        dns_cache_ip_to_name[ip_addr_str] = agent_fqdn
        dns_cache_ip_expires[ip_addr_str] = (
            time.time() + c_config['cache']['dns_cache_ttl_seconds'])
        msg = "cache for %s (%s) updated - set to expire at %d" % \
                          (agent_fqdn, ip_addr_str, dns_cache_ip_expires[ip_addr_str])
        ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

        # FIXME ??????
        # dns_cache_ip_to_name[str(trap_dict["agent address"])]

    trap_dict["cambria.partition"] = str(trap_dict["agent name"])
    trap_dict["community"] = ""    # do not include cleartext community in pub
    trap_dict["community len"] = 0

    # FIXME.CHECK_WITH_DOWNSTREAM_CONSUMERS: get rid of round for millisecond val
    # epoch_second = int(round(time.time()))
    epoch_msecond = time.time()
    epoch_second = int(round(epoch_msecond))
    if epoch_second == last_epoch_second:
        traps_in_epoch += 1
    else:
        traps_in_epoch = 0
    last_epoch_second = epoch_second
    traps_in_epoch_04d = format(traps_in_epoch, '04d')
    trap_dict['epoch_serno'] = int(
        (str(epoch_second) + str(traps_in_epoch_04d)))

    snmp_version = variables['securityModel']
    if snmp_version == 1:
        trap_dict["protocol version"] = "v1"
    else:
        if snmp_version == 2:
            trap_dict["protocol version"] = "v2c"
        else:
            if snmp_version == 3:
                trap_dict["protocol version"] = "v3"
            else:
                trap_dict["protocol version"] = "unknown"

    if snmp_version == 3:
        trap_dict["protocol version"] = "v3"
        trap_dict["security level"] = str(variables['securityLevel'])
        trap_dict["context name"] = str(variables['contextName'].prettyPrint())
        trap_dict["security name"] = str(variables['securityName'])
        trap_dict["security engine"] = str(
            variables['contextEngineId'].prettyPrint())
    trap_dict['time received'] = epoch_msecond
    trap_dict['trap category'] = (c_config['streams_publishes']['sec_fault_unsecure']['dmaap_info']['topic_url']).split('/')[-1]


# # # # # # # # # # # # # # # # # # #
# fx: request_observer for community string rewrite
# # # # # # # # # # # # # # # # # # #
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

    # note: keeping individual_vb_dict global so we don't have to malloc each time in
    global all_vb_json_str, trap_dict, individual_vb_dict, first_varbind

    # msg = "adding %s %s <begin_value> %s <end_value> to all_vb_json_str: %s" % \
    #                  (vb_oid.prettyPrint(), vb_type, vb_val.prettyPrint(), all_vb_json_str)
    # ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    if trap_dict["protocol version"] == "v2c":
        # if v2c and first 2 varbinds, special handling required - e.g. put
        # in trap_dict, not vb_json_str
        if vb_idx == 0:
            trap_dict["sysUptime"] = str(vb_val.prettyPrint())
            return True
        else:
            if vb_idx == 1:
                trap_dict["notify OID"] = str(vb_val.prettyPrint())
                trap_dict["notify OID len"] = (
                    trap_dict["notify OID"].count('.') + 1)
                return True
    if first_varbind:
        all_vb_json_str = ', \"varbinds\": ['
        first_varbind = False
    else:
        # all_vb_json_str = ''.join([all_vb_json_str, ' ,'])
        # all_vb_json_str = "%s ," % all_vb_json_str
        all_vb_json_str = all_vb_json_str + " ," 

    individual_vb_dict.clear()
    individual_vb_dict['varbind_oid'] = vb_oid.prettyPrint()
    individual_vb_dict['varbind_type'] = vb_type
    individual_vb_dict['varbind_value'] = vb_val.prettyPrint()
    # msg = ("individual_vb_dict: %s" % (individual_vb_dict))
    # ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    individual_vb_json_str = json.dumps(individual_vb_dict)
    # msg = "individual_vb_json_string for this varbind: %s" % \
    #                 (individual_vb_json_str)
    #ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    # all_vb_json_str = "%s%s" % (all_vb_json_str, individual_vb_json_str)
    # all_vb_json_str = ''.join([all_vb_json_str, individual_vb_json_str])
    all_vb_json_str = all_vb_json_str + individual_vb_json_str
    return True


# Callback function for receiving notifications
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def notif_receiver_cb(snmp_engine, stateReference, contextEngineId, contextName,
                      varBinds, cbCtx):
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

    global c_config, trap_dict, all_vb_json_str, first_trap, first_varbind, trap_uuids_in_buffer, all_traps_str, traps_since_last_publish

    msg = "processing varbinds for %s" % (trap_dict["uuid"])
    ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    # FIXME update reset location when batching publishes
    vb_idx = 0

    # For reference: 
    #
    # print('\nvarBinds ==> %s' % (varBinds))
    #
    # varBinds ==> [(ObjectName('1.3.6.1.2.1.1.3.0'), TimeTicks(1243175676)),
    #               (ObjectName('1.3.6.1.6.3.1.1.4.1.0'), ObjectIdentifier('1.3.6.1.4.1.74.2.46.12.1.1')),
    #               (ObjectName('1.3.6.1.4.1.74.2.46.12.1.1.1'), OctetString(b'ucsnmp heartbeat - ignore')),
    #               (ObjectName('1.3.6.1.4.1.74.2.46.12.1.1.2'), OctetString(b'Fri Aug 11 17:46:01 EDT 2017'))]
    #

    all_vb_json_str = ""
    vb_idx = 0
    first_varbind = True

    # iterate over varbinds, add to json struct
    for vb_oid, vb_val in varBinds:
        add_varbind_to_json(vb_idx, vb_oid, vb_val.__class__.__name__, vb_val)
        vb_idx += 1

    # msg = "varbind: %d all_vb_json_str: %s" % (vb_idx, all_vb_json_str)
    # ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    # FIXME: DL back out first 2 varbinds for v2c notifs prior to publishing varbind count
    # trap_dict["varbind count"] = vb_idx
    curr_trap_json_str = json.dumps(trap_dict)
    # now have everything except varbinds in "curr_trap_json_str"

    # if varbinds present - which will almost always be the case - add all_vb_json_str to trap_json_message
    if vb_idx != 0:
        # close out vb array
        # all_vb_json_str += "]"
        # all_vb_json_str = ''.join([all_vb_json_str, ']'])
        all_vb_json_str = all_vb_json_str + ']'

        # remove last close bracket from curr_trap_json_str
        curr_trap_json_str = curr_trap_json_str[:-1]

        # add vb_json_str to payload
        # curr_trap_json_str += all_vb_json_str
        # curr_trap_json_str = ''.join([curr_trap_json_str, all_vb_json_str])
        curr_trap_json_str = curr_trap_json_str + all_vb_json_str

        # add last close brace back in
        # curr_trap_json_str += "}"
        # curr_trap_json_str = ''.join([curr_trap_json_str, '}'])
        curr_trap_json_str = curr_trap_json_str + '}'

    msg = "trap %s : %s" % (trap_dict["uuid"], curr_trap_json_str)
    ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

    # now have a complete json message for this trap in "curr_trap_json_str"
    traps_since_last_publish += 1
    milliseconds_since_last_publish = (time.time() - last_pub_time) * 1000

    msg = "adding %s to buffer" % (trap_dict["uuid"])
    ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
    if first_trap:
       all_traps_str = curr_trap_json_str
       trap_uuids_in_buffer = trap_dict["uuid"]
       first_trap = False
    else:
       trap_uuids_in_buffer = trap_uuids_in_buffer + ', ' + trap_dict["uuid"]
       all_traps_str = all_traps_str + ', ' + curr_trap_json_str

    # publish to dmaap after last varbind is processed
    if traps_since_last_publish >= c_config['publisher']['max_traps_between_publishes']:
        msg = "num traps since last publish (%d) exceeds threshold (%d) - publish traps" % (traps_since_last_publish, c_config['publisher']['max_traps_between_publishes'])
        ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
        post_dmaap()
    elif milliseconds_since_last_publish >= c_config['publisher']['max_milliseconds_between_publishes']:
        msg = "num milliseconds since last publish (%.0f) exceeds threshold - publish traps"% milliseconds_since_last_publish
        ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
        post_dmaap()


# # # # # # # # # # # # #
# Main  MAIN  Main  MAIN
# # # # # # # # # # # # #
# parse command line args
parser = argparse.ArgumentParser(description='Post SNMP traps '
                                             'to message bus')
parser.add_argument('-v', action="store_true", dest="verbose",
                    help="verbose logging")
parser.add_argument('-?', action="store_true", dest="usage_requested",
                    help="show command line use")

# parse args
args = parser.parse_args()

# set vars from args
verbose = args.verbose
usage_requested = args.usage_requested

# if usage, just display and exit
if usage_requested:
    usage_err()

# Set initial startup hour for rolling logfile
last_hour = datetime.datetime.now().hour

# get config binding service (CBS) values (either broker, or json file override)
load_all_configs(0,0)
msg = "%s : %s version %s starting" % (prog_name, c_config['info']['title'], c_config['info']['version'])
stdout_logger(msg)

# Avoid this unless needed for testing; it prints sensitive data to log
#
# msg = "Running config: "
# stdout_logger(msg)
# msg = json.dumps(c_config, sort_keys=False, indent=4)
# stdout_logger(msg)

# open various ecomp logs
eelf_log_open(c_config)

# bump up logging level if overridden at command line
if verbose:
    msg = "log level reduced to 0 (all messages will be logged - WARNING:  This can slow things down, use only when needed...)"
    current_min_sev_log_level=0
    stdout_logger(msg)

# name and open json trap log
json_log_filename = c_config['files']['runtime_base_dir'] + "/" + c_config['files']['log_dir'] + "/" + "DMAAP_" + (c_config['streams_publishes']['sec_fault_unsecure']['dmaap_info']['topic_url'].split('/')[-1]) + ".json"
msg = ("opening json output: %s" % json_log_filename)
ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
json_fd = open_json_log()

msg = ("published traps logged to: %s" % json_log_filename)
stdout_logger(msg)
ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)

# setup signal handling for config reload
signal.signal(signal.SIGUSR1, load_all_configs)

# save current PID for future/external reference
pid_file_name = c_config['files']['runtime_base_dir'] + \
    '/' + c_config['files']['pid_dir'] + '/' + prog_name + ".pid"
msg = "Runtime PID file: %s" % pid_file_name
ecomp_logger(c_config, LOG_TYPE_DEBUG, SEV_INFO, CODE_GENERAL, msg)
rc = save_pid(pid_file_name)

# Get the event loop for this thread
loop = asyncio.get_event_loop()

# Create SNMP engine with autogenernated engineID pre-bound
# to socket transport dispatcher
snmp_engine = engine.SnmpEngine()

# # # # # # # # # # # #
# Transport setup
# # # # # # # # # # # #

# UDP over IPv4
# FIXME:  add check for presense of ipv4_interface prior to attempting add OR just put entire thing in try/except clause
try:
    ipv4_interface = c_config['protocols']['ipv4_interface']
    ipv4_port = c_config['protocols']['ipv4_port']

    try:
        config.addTransport(
            snmp_engine,
            udp.domainName + (1,),
            udp.UdpTransport().openServerMode(
                (c_config['protocols']['ipv4_interface'], c_config['protocols']['ipv4_port']))
        )
    except Exception as e:
        msg = "Unable to bind to %s:%s - %s" % (c_config['protocols']['ipv4_interface'], c_config['protocols']['ipv4_port'], str(e))
        ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_FATAL, CODE_GENERAL, msg)
        cleanup_and_exit(1, pid_file_name)

except Exception as e:
    msg = "IPv4 interface and/or port not specified in config - not listening for IPv4 traps"
    ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_WARN, CODE_GENERAL, msg)


# UDP over IPv4, second listening interface/port example if you don't want to listen on all
# config.addTransport(
#     snmp_engine,
#     udp.domainName + (2,),
#     udp.UdpTransport().openServerMode(('127.0.0.1', 2162))
# )


# UDP over IPv6
# FIXME:  add check for presense of ipv6_interface prior to attempting add OR just put entire thing in try/except clause
try:
    ipv6_interface = c_config['protocols']['ipv4_interface']
    ipv6_port = c_config['protocols']['ipv4_port']

    try:
        config.addTransport(
            snmp_engine,
            udp6.domainName,
            udp6.Udp6Transport().openServerMode(
                (c_config['protocols']['ipv6_interface'], c_config['protocols']['ipv6_port']))
        )
    except Exception as e:
        msg = "Unable to bind to %s:%s - %s" % (c_config['protocols']['ipv6_interface'], c_config['protocols']['ipv6_port'], str(e))
        ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_FATAL, CODE_GENERAL, msg)
        cleanup_and_exit(1, pid_file_name)

except Exception as e:
    msg = "IPv6 interface and/or port not specified in config - not listening for IPv6 traps"
    ecomp_logger(c_config, LOG_TYPE_ERROR, SEV_WARN, CODE_GENERAL, msg)


# # # # # # # # # # # #
# SNMPv1/2c setup
# # # # # # # # # # # #

# SecurityName <-> CommunityName mapping
#     to restrict trap reception to only those with specific community
#     strings
config.addV1System(snmp_engine, 'my-area', 'public')

# register comm_string_rewrite_observer for message arrival
snmp_engine.observer.registerObserver(
    comm_string_rewrite_observer,
    'rfc2576.processIncomingMsg:writable'
)

# register snmp_engine_observer_cb for message arrival
snmp_engine.observer.registerObserver(
    snmp_engine_observer_cb,
    'rfc3412.receiveMessage:request',
    'rfc3412.returnResponsePdu',
)

# Register SNMP Application at the SNMP engine
ntfrcv.NotificationReceiver(snmp_engine, notif_receiver_cb)

snmp_engine.transportDispatcher.jobStarted(1)  # loop forever

# Run I/O dispatcher which will receive traps
try:
    snmp_engine.transportDispatcher.runDispatcher()
except:
    snmp_engine.observer.unregisterObserver()
    snmp_engine.transportDispatcher.closeDispatcher()
    cleanup_and_exit(1, pid_file_name)
