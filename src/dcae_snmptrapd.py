# ============LICENSE_START=======================================================)
# org.onap.dcae
# ================================================================================
# Copyright (c) 2017,2018 AT&T Intellectual Property. All rights reserved.
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
It's behavior is controlled by several configs, the primary being:

    ../etc/trapd.yaml

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
import yaml

# pysnmp
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp, udp6
# from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c

# gen2 controller
from onap_dcae_cbs_docker_client.client import get_config

# dcae_snmptrap
from trapd_runtime_pid import save_pid, rm_pid
from trapd_yaml_config import read_yaml_config
from trapd_trap_config import read_trap_config
from trapd_dmaap_config import read_dmaap_config
from trapd_exit import cleanup_and_exit
from trapd_http_session import init_session_obj
from trapd_perm_status import log_to_perm_status

prog_name = os.path.basename(__file__)

traps_in_second = 0
last_epoch_second = 0

# <dmaap.conf>
dmaap_url = ""
dmaap_user_name = ""
dmaap_p_var = ""
dmaap_stream_id = ""
dmaap_host = ""
# </dmaap.conf>

# Requests session object
dmaap_requests_session = None
http_headers = {"Content-type": "application/json"}

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
num_trap_conf_entries = 0
trap_conf_dict = {}
# </trap config>

pid_file_name = ""

# logging
dcae_logger = logging.getLogger('dcae_logger')
handler = ""
dcae_logger_max_bytes = 60000000
dcae_logger_num_archives = 10

undefined = "undefined"
rc = 0
usage_requested = False

json_fd = None
last_hour = -1

verbose = False

trap_dict = {}

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

    print('Correct usage:')
    print('  %s -c <yaml_conf_file_name> [-v]' % prog_name)
    cleanup_and_exit(1, "undefined")


# # # # # # # # # # # # # # # # # # #
# fx: setup dcae_logger custom logger
# # # # # # # # # # ## # # # # # # #
def setup_dcae_logger(_yc_trapd_diag):
    """
    Setup custom logger for dcae_snmptrapd that incorporates
    a rotating file handler with 10 backups of diagnostic messages
    :Parameters:
       _yc_trapd_diag - the full path output filename
    :Exceptions:
       none
    :Keywords:
       logging rotation
    """

    global dcae_logger
    global handler

    date_fmt = '%m/%d/%Y %H:%M:%S'

    _yc_trapd_diag_bak = "%s.bak" % (_yc_trapd_diag)
    if os.path.isfile(_yc_trapd_diag):
        os.rename(_yc_trapd_diag, _yc_trapd_diag_bak)

    # handler = logging.handlers.RotatingFileHandler(yc_trapd_diag, maxBytes=60000000, backupCount=10)
    handler = logging.handlers.RotatingFileHandler(_yc_trapd_diag,
                                                   maxBytes=dcae_logger_max_bytes,
                                                   backupCount=dcae_logger_num_archives)

    # set logLevel - valid values NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL
    handler.setLevel(logging.DEBUG)
    dcae_logger.setLevel(logging.DEBUG)

    log_fmt = '%(levelname)s|%(asctime)s|%(name)s|%(process)d|%(funcName)s|'\
              '%(message)s'
    formatter = logging.Formatter(log_fmt)
    handler.setFormatter(formatter)
    dcae_logger.addHandler(handler)

    if os.path.isfile(_yc_trapd_diag):
        os.chmod(_yc_trapd_diag, 0o640)

    if os.path.isfile(_yc_trapd_diag_bak):
        os.chmod(_yc_trapd_diag_bak, 0o640)


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
      dmaap_requests_session
    """

    if int(_signum) != 0:
        dcae_logger.info("%s Received signal %s at frame %s; re-reading config file"
                         % (prog_name, _signum, _frame))
    else:
        dcae_logger("Reading config files")

    # FIXME: should be re-reading all configs here

    # Initialize dmaap requests session object. Close existing session
    # if applicable.
    if dmaap_requests_session != None:
        dmaap_requests_session.close()
    dmaap_requests_session = init_session_obj(dcae_logger)

    return _yaml_config_values


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
        os.rename(_outputFname, _outputFnameBak)
    else:
        dcae_logger.error("Unable to move %s to %s - source file does not exist" %
                          (_outputFname, _outputFnameBak))
    # open new (empty) log file
    try:
        json_fd = open_json_log()
    except:
        dcae_logger.exception(
            "Error opening new json log file %s - exiting  " % _outputFname)
        sys.exit(1)

# # # # # # # # # # # # #
# fx: open_json_log
# # # # # # # # # # # # #
def open_json_log():

    try:
        # open append mode just in case so nothing is lost, but should be
        # non-existent file
        _json_fd = open(json_log_filename, 'a')
        dcae_logger.exception("Opened %s append mode: " % json_log_filename)
        return _json_fd
    except:
        dcae_logger.exception(
            "Error opening %s append mode: " % json_log_filename)
        sys.exit(1)


# # # # # # # # # # # # #
# fx: close_json_log
# # # # # # # # # # # # #
def close_json_log():

    global json_fd

    try:
        json_fd.close()
    except:
        dcae_logger.error("ERROR closing json audit file %s - results "
                          "indeterminate" % (json_log_filename))

# # # # # # # # # # # # #
# fx: log_published_messages
# # # # # # # # # # # # #


def log_published_messages(loc_post_data_enclosed):

    # FIXME: should keep data dictionary of Fd's open, and reference those vs.
    #        repeatedly opening append-mode
    # open json audit log file

    global json_fd, last_hour

    # close output file, backup current and move new one into place on day change
    dcae_logger.info('%.4f adding %s to json log' %
                     (time.time(), trap_dict["uuid"]))
    curr_hour = datetime.datetime.now().hour
    if curr_hour < last_hour:
        rename_json_log(json_log_filename)
        json_fd = open_json_log(json_log_filename)

    try:
        m = loc_post_data_enclosed + '\n'
        json_fd.write('%s' % str(m))
    except Exception as e:
        dcae_logger.error("ERROR writing json audit file %s - message NOT LOGGED: %s"
                          % (json_log_filename, str(e)))

    last_hour = curr_hour
    dcae_logger.info('%.4f logged %s' % (time.time(), trap_dict["uuid"]))

# # # # # # # # # # # # #
# fx: post_dmaap
# # # # # # # # # # # # #


def post_dmaap(dmaap_url, dmaap_user_name, dmaap_p_var, dmaap_stream_id, dmaap_host, uuid, traps_json_string):
    """
    Publish trap daata in json format to dmaap
    :Parameters:
      dmaap_url
         base url for http post
      dmaap_user_name
         username for http post
      dmaap_p_var
         access credential for http post
      dmaap_stream_id
         appended to dmaap_url, equiv to "topic"
      dmaap_host
         target dmaap server to submit http post
      uuid
         unique ID associated with this trap
      traps_json_string
         json format string to include in http post
    :Exceptions:
      none
    :Keywords:
      http post dmaap json message
    :Variables:
    """

    global http_resp, dmaap_requests_session, last_pub_time

    if dmaap_requests_session == None:
        dmaap_requests_session = init_session_obj(dcae_logger)

    post_data_enclosed = '[' + traps_json_string + ']'

    k = 0
    dmaap_pub_success = False

    if verbose:
        print('%.4f starting publish of %s' % (time.time(), trap_dict["uuid"]))
    dcae_logger.info('%.4f starting publish of %s' %
                     (time.time(), trap_dict["uuid"]))
    while not dmaap_pub_success and k < yaml_config_values.yc_http_retries:
        try:
            dcae_logger.debug("Attempt %d to %s dmaap_url: "
                              "%s dmaap_user_name: %s post_data: %s"
                              % (k, dmaap_host,
                                 dmaap_url,
                                 dmaap_user_name,
                                 post_data_enclosed))

            # below disable_warnings required until python updated:
            #       https://github.com/shazow/urllib3/issues/497
            # requests.packages.urllib3.disable_warnings()
            http_resp = dmaap_requests_session.post(dmaap_url, post_data_enclosed,
                                                    auth=(dmaap_user_name,
                                                          dmaap_p_var),
                                                    headers=http_headers,
                                                    timeout=yaml_config_values.yc_http_timeout)
            dcae_logger.debug("Response from %s on stream %s: %s dmaap_requests_session: %s"
                              % (dmaap_host, dmaap_stream_id, http_resp.status_code, dmaap_requests_session))
            if verbose:
                print('%.4f published %s successfully' %
                      (time.time(), trap_dict["uuid"]))
            dcae_logger.info('%.4f published %s successfully' %
                             (time.time(), trap_dict["uuid"]))
            if http_resp.status_code == requests.codes.ok:
                dcae_logger.debug("Response from %s: %s dmaap_request_sesson: %s" % (
                    dmaap_url, http_resp.status_code, dmaap_requests_session))
                log_published_messages(post_data_enclosed)
                last_pub_time = time.time()
                dmaap_pub_success = True
                break
            else:
                dcae_logger.debug("Response (non-200) detail from %s on stream "
                                  "%s: %s" % (dmaap_host, dmaap_stream_id, http_resp.text))

        except OSError as e:
            dcae_logger.debug("Exception while posting message to host: %s, stream: %s, dmaap_requests_session: %s, exception: %s %s"
                              % (dmaap_host, dmaap_stream_id, dmaap_requests_session, e.errno, e.strerror))
        except requests.exceptions.RequestException as e:
            dcae_logger.error("Exception while posting to %s topic %s: -->%s<--"
                              % (dmaap_host, dmaap_stream_id, e))

        k += 1

        if k < yaml_config_values.yc_http_retries:
            dcae_logger.error("sleeping %s and retrying" %
                              yaml_config_values.yc_http_secs_between_retries)
            time.sleep(yaml_config_values.yc_http_secs_between_retries)
        else:
            dcae_logger.error("exhausted all attempts - giving up")
            break

    if verbose:
        print('%.4f exiting post_dmaap for %s' %
              (time.time(), trap_dict["uuid"]))
    dcae_logger.info('%.4f exiting post_dmaap for %s' %
                     (time.time(), trap_dict["uuid"]))
    if not dmaap_pub_success:
        # uuid = uuid_mod.uuid1()
        perm_msg = "CRITICAL: publish failure to DMAAP server: "\
                   "%s, stream: %s trap: %s" % (
                       dmaap_host, dmaap_stream_id, uuid)
        dcae_logger.error(perm_msg)
        dcae_logger.error("SEND-TO-PERM-STATUS: %s" % perm_msg)
        log_to_perm_status(
            yaml_config_values.yc_perm_status_file, perm_msg, dcae_logger)
        dcae_logger.info("%.4f %s" % (time.time(), perm_msg))
        if verbose:
            print("%.4f %s" % (time.time(), perm_msg))


# # # # # # # # # # # # # # # # # # #
# fx: request_observer for community string rewrite
# # # # # # # # # # # # # # # # # # #
def comm_string_rewrite_observer(snmpEngine, execpoint, variables, cbCtx):

    # match ALL community strings
    if re.match('.*', str(variables['communityName'])):
        dcae_logger.debug('Rewriting communityName \'%s\' from %s into \'public\'' % (variables['communityName'], ':'.join([str(x) for x in
                                                                                                                            variables['transportInformation'][1]])))
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

    if verbose:
        print('%.4f snmp trap arrived from %s, assigned uuid: %s' %
              (time.time(), variables['transportAddress'][0], trap_dict["uuid"]))
    dcae_logger.info('%.4f snmp trap arrived from %s, assigned uuid: %s' % (
        time.time(), variables['transportAddress'][0], trap_dict["uuid"]))

    # if re.match('.*', str(variables['communityName'])):
    #     print('Rewriting communityName \'%s\' from %s into \'public\'' % (variables['communityName'], ':'.join([str(x) for x in variables['transportInformation'][1]])))
    #    variables['communityName'] = variables['communityName'].clone('public')

    # ip and hostname
    ip_addr_str = str(variables['transportAddress'][0])
    trap_dict["agent address"] = ip_addr_str
    try:
        if int(dns_cache_ip_expires[ip_addr_str] < int(time.time())):
            dcae_logger.debug('dns cache expired for %s' % ip_addr_str)
            raise Exception('cache expired for %s at %d - updating value' %
                            (ip_addr_str, (dns_cache_ip_expires[ip_addr_str])))
        else:
            trap_dict["agent name"] = dns_cache_ip_to_name[ip_addr_str]
    except:
        if verbose:
            print('%.4f dns cache expired for %s' % (time.time(), ip_addr_str))
        dcae_logger.debug(
            'dns cache expired or missing for %s - reloading' % ip_addr_str)
        host_addr_info = socket.gethostbyaddr(ip_addr_str)
        agent_fqdn = str(host_addr_info[0])
        trap_dict["agent name"] = agent_fqdn

        dns_cache_ip_to_name[ip_addr_str] = agent_fqdn
        dns_cache_ip_expires[ip_addr_str] = (
            time.time() + yaml_config_values.yc_dns_cache_ttl_seconds)
        dcae_logger.debug('cache for %s (%s) updated - set to expire at %d' %
                          (agent_fqdn, ip_addr_str, dns_cache_ip_expires[ip_addr_str]))

        dns_cache_ip_to_name[str(trap_dict["agent address"])]

    trap_dict["cambria.partition"] = str(trap_dict["agent name"])
    trap_dict["community"] = ""    # do not include cleartext community in pub
    # do not include cleartext community in pub
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
    # get this from dmaap_url when ready
    trap_dict['trap category'] = "DCAE-COLLECTOR-UCSNMP"


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
        trap varbinds
      cbCtx
        callback context
    :Exceptions:
      none
    :Keywords:
      callback trap arrival
    :Variables:
    """

    global trap_dict

    if verbose:
        print('%.4f processing varbinds for %s' %
              (time.time(), trap_dict["uuid"]))
    dcae_logger.info('%.4f processing varbinds for %s' %
                     (time.time(), trap_dict["uuid"]))

    # FIXME:  add conversion from v1 to v2 prior to below? or special handling for v1?

    # FIXME update reset location when batching publishes
    vb_dict = {}

    vb_idx = 0
    k1 = ""
    k2 = ""

    # FIXME: Note that the vb type is present, just need to extract it efficiently somehow
    # print('\nvarBinds ==> %s' % (varBinds))
    #
    # varBinds ==> [(ObjectName('1.3.6.1.2.1.1.3.0'), TimeTicks(1243175676)),
    #               (ObjectName('1.3.6.1.6.3.1.1.4.1.0'), ObjectIdentifier('1.3.6.1.4.1.74.2.46.12.1.1')),
    #               (ObjectName('1.3.6.1.4.1.74.2.46.12.1.1.1'), OctetString(b'ucsnmp heartbeat - ignore')),
    #               (ObjectName('1.3.6.1.4.1.74.2.46.12.1.1.2'), OctetString(b'Fri Aug 11 17:46:01 EDT 2017'))]
    #
    # This does NOT work:
    # for name, typ, val in varBinds:
    #     print('name = %s' % (name))
    #     print('typ = %s' % (typ))
    #     print('val = %s\n' % (val))

    vb_all_string = ""
    for name, val in varBinds:
        vb_dict = {}
        if vb_idx == 0:
            vb_sys_uptime_oid = name
            vb_sys_uptime = val
            trap_dict["sysUptime"] = str(val)
            # print('vb_sys_uptime = %s' % (vb_sys_uptime))
        else:
            if vb_idx == 1:
                trap_dict["notify OID"] = str(val)
                trap_dict["notify OID len"] = (
                    trap_dict["notify OID"].count('.') + 1)
                # print('vb_notify_oid = %s' % (vb_notify_oid))
            # else:
                # vb_idx_02d = format((vb_idx - 2), '02d')
        vb_idx_02d = format((vb_idx), '02d')

        k1 = "varbind_oid_" + str(vb_idx_02d)
        k2 = "varbind_value_" + str(vb_idx_02d)
        # vb_dict[k1] = name.prettyPrint()
        # vb_dict[k2] = val.prettyPrint()
        vb_dict["varbind_type"] = "tbd"
        vb_dict["varbind_oid"] = name.prettyPrint()
        vb_dict["varbind_value"] = val.prettyPrint()
        vb_json = json.dumps(vb_dict)
        vb_all_string += vb_json

        vb_idx += 1

    trap_dict["num varbinds"] = vb_idx

    # add varbind dict to trap dict
    # trap_dict["varbinds"] = vb_dict
    trap_dict["varbinds"] = vb_all_string

    dcae_logger.debug("vb_dict json-ized: %s" % (json.dumps(vb_dict)))
    trap_json_msg = json.dumps(trap_dict)

    # publish to dmaap after last varbind is processed
    post_dmaap(dmaap_config_values.dmaap_url, dmaap_config_values.dmaap_user_name, dmaap_config_values.dmaap_p_var,
               dmaap_config_values.dmaap_stream_id, dmaap_config_values.dmaap_host, trap_dict["uuid"], trap_json_msg)


# # # # # # # # # # # # #
# Main  MAIN  Main  MAIN
# # # # # # # # # # # # #
# parse command line args
parser = argparse.ArgumentParser(description='Post SNMP traps '
                                             'to DCAE DMaap MR')
parser.add_argument('-c', action="store", dest="yaml_conf_file", type=str,
                    help="yaml config file name")
parser.add_argument('-v', action="store_true", dest="verbose",
                    help="verbose logging")
parser.add_argument('-?', action="store_true", dest="usage_requested",
                    help="show command line use")

# set vars from args
parser.set_defaults(yaml_conf_file="")

# parse args
args = parser.parse_args()

# set vars from args
yaml_conf_file = args.yaml_conf_file
verbose = args.verbose
usage_requested = args.usage_requested

# if usage, just display and exit
if usage_requested:
    usage_err()

# Get non-ENV settings from config file; spoof 2 params
# so same fx can be used for signal handling
if yaml_conf_file == "":
    usage_err()

# always get yaml config values
yaml_config_values = read_yaml_config(yaml_conf_file)

# setup custom logger
setup_dcae_logger(yaml_config_values.yc_trapd_diag)

# bump up logging level if overridden at command line
if verbose:
    dcae_logger.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
    dcae_logger.debug("log level increased to DEBUG")

dcae_logger.info("log will include info level messages")
dcae_logger.error("log will include error level messages")
dcae_logger.debug("log will include debug level messages")
dcae_logger.info("Runtime PID file: %s" % pid_file_name)

# setup signal handling for config file reload
# FIXME: need to have signal handler return all tuples for configs
# signal.signal(signal.SIGUSR1, load_all_configs)

# save current PID for future/external reference
pid_file_name = '%s/%s.pid' % (yaml_config_values.yc_pid_dir, prog_name)
rc = save_pid(pid_file_name)

# always get trap configs
trap_config_values = read_trap_config(
    yaml_config_values.yc_trap_conf, dcae_logger)

# Set initial startup hour for rolling logfile
last_hour = datetime.datetime.now().hour

#make sure my env is set properly
try:
   c = get_config()
   if c == {}:
       msg = "Unable to fetch configuration or it is erroneously empty - fatal ONAP controller error, trying OpenDCAE config"
       dcae_logger.error(msg)
       print('%s' % msg)

#if new controller not present, try dmaap.conf
except:
    msg = "ONAP controller not present, attempting OpenDCAE dmaap.conf config"
    dcae_logger.error(msg)
    dmaap_config_values = read_dmaap_config(
        yaml_config_values.yc_dmaap_conf, dcae_logger)

    # get the topic from the url
    dmaap_topic = dmaap_config_values.dmaap_url.split('.')[-1]
    dcae_logger.info("Topic: %s" % dmaap_topic)
    json_log_filename = yaml_config_values.yc_published_traps_dir + '/' + 'DMAAP' + '_' \
        + dmaap_topic + '.json'
    json_fd = open_json_log()
    msg = "Using OpenDCAE dmaap.conf config"

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
config.addTransport(
    snmp_engine,
    udp.domainName + (1,),
    udp.UdpTransport().openServerMode(
        (yaml_config_values.yc_ipv4_interface, yaml_config_values.yc_ipv4_port))
)

# UDP over IPv6
# FIXME:  add check for presense of ipv6_interface prior to attempting add OR just put entire thing in try/except clause
config.addTransport(
    snmp_engine,
    udp6.domainName,
    udp6.Udp6Transport().openServerMode(
        (yaml_config_values.yc_ipv6_interface, yaml_config_values.yc_ipv6_port))
)

# UDP over IPv4, second listening interface/port
# config.addTransport(
#     snmp_engine,
#     udp.domainName + (2,),
#     udp.UdpTransport().openServerMode(('127.0.0.1', 2162))
# )

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

# Run I/O dispatcher which would receive queries and send confirmations
try:
    snmp_engine.transportDispatcher.runDispatcher()
except:
    snmp_engine.observer.unregisterObserver()
    snmp_engine.transportDispatcher.closeDispatcher()
    cleanup_and_exit(1, pid_file_name)
