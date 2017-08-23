#
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

import argparse
from array import *
import asyncio 
from collections import Counter
import datetime
import json 
import logging
import logging.handlers
from optparse import OptionParser
import os
import pprint
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
# from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
import requests
import sys
import signal
import string
import socket
import time
import traceback
import unicodedata
import uuid as uuid_mod
import yaml

prog_name=os.path.basename(__file__)

traps_in_second = 0
last_epoch_second = 0

ueb_partition = ""

# <yaml config file values>
# yc_ -> "yaml config_" -if you see this prefix, it came from conf file
#    protocol
yc_transport = ""
yc_interface = ""
yc_port = 162
yc_dns_cache_ttl_seconds = 0

#    files
yc_runtime_base_dir = ""
yc_log_dir = ""
yc_data_dir = ""
yc_pid_dir = ""
yc_dcae_snmptrapd_diag = ""
yc_raw_traps_log = ""
yc_published_traps_dir = ""
yc_trap_stats_log = ""
yc_perm_status_file = ""

#    ueb
yc_dmaap_conf = ""
yc_http_timeout = 5.0
yc_primary_publisher = ""
yc_peer_publisher = ""
yc_max_traps_between_publish = 0 # max number of traps to batch before publishing
yc_max_milliseconds_between_publish = 0 # max number of seconds between publishing
# </yaml config file values>

# <dmaap.conf>
dmaap_url = ""
dmaap_user_name = ""
dmaap_p_var = ""
dmaap_stream_id = ""
# </dmaap.conf>

# Requests session object (ueb and dmaap).
dmaap_request_session = ""
http_headers = {"Content-type": "application/json"}

# FIXME: temp resource for UEB publishes
ueb_url = ""

# <DNS cache>
#
#     dns_cache_ip_to_name
#        key [ip address] -> fqdn
#     dns_cache_ip_expires 
#        key [ip address] -> epoch this entry expires at
dns_cache_ip_to_name = {}
dns_cache_ip_expires = {}
# </DNS cache>

# logging
dcae_logger = logging.getLogger('dcae_logger')
handler = ""

# # # # # # # # # # # # # # # # # # #
# fx: setup dcae_logger custom logger
# # # # # # # # # # ## # # # # # # #
def setup_dcae_logger():
    """
    Setup custom logger for dcae_snmptrapd that incorporates 
    a rotating file handler with 10 backups of diagnostic
    log file.
    :Parameters:
       none
    :Exceptions:
       none
    :Keywords:
       logging
    """

    global dcae_logger, verbose
    global handler

    date_fmt = '%m/%d/%Y %H:%M:%S'

    yc_dcae_snmptrapd_diag_bak = "%s.bak" % (yc_dcae_snmptrapd_diag)
    if os.path.isfile(yc_dcae_snmptrapd_diag):
        os.rename(yc_dcae_snmptrapd_diag, yc_dcae_snmptrapd_diag_bak)

    handler = logging.handlers.RotatingFileHandler(yc_dcae_snmptrapd_diag, maxBytes=60000000, backupCount=10)

    # set logLevel - valid values NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL
    handler.setLevel(logging.DEBUG)
    dcae_logger.setLevel(logging.DEBUG)

    log_fmt = '%(levelname)s|%(asctime)s|%(name)s|%(process)d|%(funcName)s|'\
              '%(message)s'
    formatter = logging.Formatter(log_fmt)
    handler.setFormatter(formatter)
    dcae_logger.addHandler(handler)

    if os.path.isfile(yc_dcae_snmptrapd_diag):
        os.chmod(yc_dcae_snmptrapd_diag, 0o640)

    if os.path.isfile(yc_dcae_snmptrapd_diag_bak):
        os.chmod(yc_dcae_snmptrapd_diag_bak, 0o640)

 
# # # # # # # # # # # # #
# fx: save_pid - save PID of running process
# # # # # # # # # # # # #
def save_pid(loc_pid_file_name):
    """
    Save the current process ID in a file for external 
    access.
    :Parameters:
      loc_pid_file_name
        filename including full path to write current process ID to 
    :Exceptions:
      file open
        this function will throw an exception if unable to open loc_pid_file_name 
    :Keywords:
      pid /var/run
    """

    try:
        pid_fd = open(loc_pid_file_name, 'w')
        pid_fd.write('%d' % os.getpid())
        pid_fd.close()
    except:
        print("Error saving PID file %s :" % loc_pid_file_name)
    else:
        print("PID file %s" % loc_pid_file_name)

 
# # # # # # # # # # # # #
# fx: rm_pid - remove PID of running process
# # # # # # # # # # # # #
def rm_pid(loc_pid_file_name):
    """
    Remove the current process ID file before exiting.
    :Parameters:
      loc_pid_file_name
        filename that contains current process ID to be removed
    :Exceptions:
      file open
        this function will throw an exception if unable to find or remove 
        loc_pid_file_name 
    :Keywords:
      pid /var/run
    """

    try:
        if os.path.isfile(loc_pid_file_name):
            os.remove(loc_pid_file_name)
    except:
        print("Error removing PID file %s" % loc_pid_file_name)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# function: get_yaml_cfg
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
def get_yaml_cfg(loc_yaml_conf_file):
    """
    Load all sorts of goodies from yaml config file.
    :Parameters:
      loc_yaml_conf_file
        filename including full path to yaml config file
    :Exceptions:
      file open
        this function will throw an exception if unable to open
        loc_yaml_conf_file (fatal error) or any of the required
        values are not found in the loc_yaml_conf_file (fatal error)
    :Keywords:
      yaml config runtime protocol files ueb
    :Variables:
      yc_transport 
        protocol transport for snmp traps (udp|tcp)
      yc_interface 
        what interface to listen for traps on
      yc_port
        what port to listen for traps on
      yc_dns_cache_ttl_seconds
        how many seconds an entry remains in DNS cache prior to refresh
      yc_runtime_base_dir 
        base directory of dcae_snmptrapd application
      yc_log_dir 
        log directory of dcae_snmptrapd application
      yc_data_dir 
        data directory of dcae_snmptrapd application
      yc_pid_dir 
        directory where running PID file will be written (filename <yc_pid_dir>/<prog_name>.pid)
      yc_dcae_snmptrapd_diag 
        program diagnostic log, auto rotated and archived via python handler
      yc_raw_traps_log
        file to write raw trap data to
      yc_published_traps_dir
        file to write json formatted trap data for successful publishes (only!)
      yc_trap_stats_log
        file to write trap stats (traps per second, by OID, by agent)
      yc_perm_status_file 
        file to write trap stats (traps per second, by OID, by agent)
      yc_dmaap_conf
        file (full path) of yaml config entries referenced at runtime, passed as 
        runtime command argument "-c <yc_dmaap_conf>
      yc_http_timeout
        http timeout in seconds for dmaap publish attempt
      yc_primary_publisher
        boolean defining whether local instance is primary (future use)
      yc_peer_publisher
        identity of peer publisher in case this one fails (future use)
      yc_max_traps_between_publish
        if batching publishes, max number of traps to queue before http post
      yc_max_milliseconds_between_publish
        if batching publishes, max number of milliseconds between http post
        Note:  using the batch feature creates an opportunity for trap loss if 
        traps stop arriving and the process exits (traps in queue will remain
        there until another trap arrives and kicks of the evaluation of max_traps
        or max_milliseconds above).
    """

    global yc_transport, yc_port, yc_interface, yc_dns_cache_ttl_seconds, yc_runtime_base_dir, yc_log_dir, yc_data_dir, yc_pid_dir, yc_dcae_snmptrapd_diag, yc_raw_traps_log, yc_published_traps_dir, yc_trap_stats_log, yc_perm_status_file, yc_dmaap_conf, yc_http_timeout, yc_primary_publisher, yc_peer_publisher, yc_max_traps_between_publish, yc_max_milliseconds_between_publish

    with open(loc_yaml_conf_file, 'r') as yaml_fd:
        cfg_data = yaml.load(yaml_fd)

    # ONAP FIXME: split try into per-section except loops below
    try:
        # protocol
        yc_transport = (cfg_data['protocol']['transport'])
        yc_interface = (cfg_data['protocol']['interface'])
        yc_port = int(cfg_data['protocol']['port'])
        yc_dns_cache_ttl_seconds = int(cfg_data['protocol']['dns_cache_ttl_seconds'])

        # files and directories
        yc_runtime_base_dir = (cfg_data['files']['runtime_base_dir'])
        yc_log_dir = (cfg_data['files']['log_dir'])
        yc_data_dir = (cfg_data['files']['data_dir'])
        yc_pid_dir = (cfg_data['files']['pid_dir'])
        yc_dcae_snmptrapd_diag = (cfg_data['files']['dcae_snmptrapd_diag'])
        yc_raw_traps_log =(cfg_data['files']['raw_traps_log'])
        yc_published_traps_dir =(cfg_data['files']['published_traps_dir'])
        yc_trap_stats_log =(cfg_data['files']['trap_stats_log'])
        yc_perm_status_file = (cfg_data['files']['perm_status_file'])

        # ueb
        yc_dmaap_conf = (cfg_data['ueb']['dmaap_conf'])
        yc_http_timeout = (cfg_data['ueb']['http_timeout'])
        yc_primary_publisher = (cfg_data['ueb']['primary_publisher'])
        yc_peer_publisher = (cfg_data['ueb']['peer_publisher'])
        yc_max_traps_between_publish = (cfg_data['ueb']['max_traps_between_publish'])
        yc_max_milliseconds_between_publish = (cfg_data['ueb']['max_milliseconds_between_publish'])

    except:
        print("ERROR reading config %s" % loc_yaml_conf_file)
        raise
        cleanup_and_exit(1)

    # print back for confirmation
    print("Read config: %s" % loc_yaml_conf_file)
    print("    protocol section:")
    print("        transport: %s" % yc_transport)
    print("        interface: %s" % yc_interface)
    print("        port: %s" % yc_port)
    print("        dns_cache_ttl_seconds: %s" % yc_dns_cache_ttl_seconds)
    print("    files section:")
    print("        runtime_base_dir: %s" % yc_runtime_base_dir)
    print("        log_dir: %s" % yc_log_dir)
    print("        data_dir: %s" % yc_data_dir)
    print("        pid_dir: %s" % yc_pid_dir)
    print("        dcae_snmptrapd_diag: %s" % yc_dcae_snmptrapd_diag)
    print("        raw_traps_log: %s" % yc_raw_traps_log)
    print("        published_traps_dir: %s" % yc_published_traps_dir)
    print("        trap_stats_log: %s" % yc_trap_stats_log)
    print("        perm_status_file: %s" % yc_perm_status_file)
    print("    ueb section:")
    print("        dmaap_config_file: %s" % yc_dmaap_conf)
    print("        http_timeout: %s" % yc_http_timeout)
    print("        primary_publisher: %s" % yc_primary_publisher)
    print("        peer_publisher: %s" % yc_peer_publisher)
    print("        max_traps_between_publish: %s" % yc_max_traps_between_publish)
    print("        max_milliseconds_between_publish: %s" % yc_max_milliseconds_between_publish)

# # # # # # # # # # #
# fx: get_dmaap_cfg
# # # # # # # # # # #
def get_dmaap_cfg():
    """
    Load dmaap config /etc/dcae/dmaap.conf file (legacy controller)
    :Parameters:
      none
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
    """

    global dmaap_url, dmaap_user_name, dmaap_p_var, dmaap_stream_id

    if os.path.isfile(yc_dmaap_conf):
        dcae_logger.debug ('Reading DMaaP config file %s ' %
                          yc_dmaap_conf)
    else:
        dcae_logger.error ('DMaaP config file %s does NOT exist - exiting'
                         % (yc_dmaap_conf))
        cleanup_and_exit(1)

    with open(yc_dmaap_conf) as dmaap_config_fd:
        dmaapCfgData = json.load(dmaap_config_fd)

    try:
        dmaap_url = dmaapCfgData [0]["dmaapUrl"]
        dmaap_user_name = dmaapCfgData [0]["dmaapUserName"]
        dmaap_p_var = dmaapCfgData [0]["dmaapPassword"]
        dmaap_stream_id = dmaapCfgData [0]["dmaapStreamId"]
    except:
        dcae_logger.error ('DMaaP config file %s has missing data - exiting'
                         % (yc_dmaap_conf))
        cleanup_and_exit(1)

    dcae_logger.debug('dmaap_url: %s' % (dmaap_url))
    dcae_logger.debug('dmaap_user_name: %s' % (dmaap_user_name))
    dcae_logger.debug('dmaap_p_var: -')
    dcae_logger.debug('dmaap_stream_id: %s' % (dmaap_stream_id))

    dmaap_config_fd.close()

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
       s = requests.Session()
       dcae_logger.debug("New requests session has been initialized")
    except:
       dcae_logger.error("Failed to create new requests session")

    return s


# # # # # # # # # # # # # # # # # # #
# fx: load_cfg
# # # # # # # # # # ## # # # # # # #
def load_cfg(_signum, _frame):
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
      dmaap_request_session
    """

    global dmaap_request_session

    if int(_signum) != 0:
        print("%s Received signal %s at frame %s; re-reading config file"
                       % (prog_name, _signum, _frame))
    else:
        print("Reading config files")

    # always get yaml config values
    get_yaml_cfg(yaml_conf_file)

    # Initialize dmaap requests session object. Close existing session
    # if applicable.
    get_dmaap_cfg()
    if dmaap_request_session:
        dmaap_request_session.close()
    dmaap_request_session = init_session_obj()
    # dcae_logger.debug("dmaap_request_session: %s" % dmaap_request_session)


# # # # # # # # # # # # # # # # # # #
# fx: post_ueb
#     temporarily publish to UEB to validate json format
# # # # # # # # # # # # # # # # # # #
def post_ueb(loc_json_msg):
    """
    This function is only present for lab testing, to allow easier unit tests
    vs. depend on (a) legacy controller or (b) next gen controller existence
    :Parameters:
      loc_json_msg
        json string of trap attributes to publish
    :Exceptions:
      none
    :Keywords:
      UEB non-AAF legacy http post
    :Variables:
    """

    global dmaap_request_session

    post_data_enclosed = '[' + loc_json_msg + ']'

    try:
        http_resp = dmaap_request_session.post(ueb_url, headers=http_headers, data=post_data_enclosed,
                            timeout=7)
        dcae_logger.debug("Response from %s: %s dmaap_request_sesson: %s" % (ueb_url, http_resp.status_code, dmaap_request_session))
        if http_resp.status_code == requests.codes.ok :
            dcae_logger.debug("trap published successfully")
        else:
            dcae_logger.debug("DMAAP returned non-normal response - ERROR")
    except:
        dcae_logger.debug("Response from %s on topic %s: %s dmaap_request_session: %s")

# # # # # # # # # # # # #
# fx: post_dmaap
# # # # # # # # # # # # #
def post_dmaap(topic, post_topics_idx, loc_num_traps_to_publish_in_topic):

    global http_resp, dmaap_url, dmaap_user_name, post_data_by_topics, drs, \
           last_pub_time

    post_data_enclosed = '[' + post_data_by_topics[post_topics_idx] + ']'

    # This is for logging purposes only.
    dmaap_host = dmaap_url.split('/')[2][:-5]

    k = 0
    dmaap_pub_success = False

    while not dmaap_pub_success and k < num_pub_attempts:
        try:
            dcae_logger.debug("Attempt %d to %s, %d traps in msg, dmaap_url: "
                            "%s dmaap_user_name: %s post_data: %s"
                            % (k, dmaap_host,
                               loc_num_traps_to_publish_in_topic, dmaap_url,
                               dmaap_user_name,
                               post_data_enclosed))

            # below disable_warnings required until python updated:
            #       https://github.com/shazow/urllib3/issues/497
            requests.packages.urllib3.disable_warnings()

            http_resp = drs.post(dmaap_url, post_data_enclosed,
                                     auth=(dmaap_user_name, dmaap_p_var),
                                     headers=http_headers,
                                     timeout=ueb_http_timeout)
            dcae_logger.debug("Response from %s on topic %s: %s drs: %s"
                            % (dmaap_host, topic, http_resp.status_code, drs))
            if http_resp.status_code == requests.codes.ok:
                dcae_logger.debug("%d traps published"
                                % loc_num_traps_to_publish_in_topic)
                log_published_messages("DMAAP", topic, post_data_enclosed)
                last_pub_time = time.time()
                dmaap_pub_success = True
            else:
                dcae_logger.debug("Response (non-200) detail from %s on topic "
                                "%s: %s" % (dmaap_host, topic, http_resp.text))

        except requests.exceptions.RequestException as e:
            dcae_logger.error("Exception while posting to %s topic %s: -->%s<--"
                           % (dmaap_host, topic, e))

        k += 1

        # No point in waiting just to log "ALL publish attempts failed" msg
        if k < num_pub_attempts:
            time.sleep(sleep_between_retries)
        else:
            break

    if not dmaap_pub_success:
        uuid = uuid_mod.uuid1()
        dcae_logger.error("ALL publish attempts failed to DMAAP server: %s, "
                        "topic: %s, %d trap(s) not published, message: %s"
                        % (dmaap_host, topic, loc_num_traps_to_publish_in_topic,
                           post_data_by_topics[post_topics_idx]))

        # Set epoch_serno range for topic
        ret_list = set_topic_serno_range(topic)
        fes = ret_list[0]
        les = ret_list[1]

        perm_msg = "CRITICAL: [%s] ALL publish attempts failed to DMAPP server: "\
                   "%s, topic: %s, %d trap(s) not published in epoch_serno "\
                   "range: %d - %d\n" \
                   % (uuid, dmaap_host, topic, loc_num_traps_to_publish_in_topic,
                      fes, les)

        dcae_logger.error("SEND-TO-PERM-STATUS: %s" % perm_msg)
        log_to_perm_status(perm_msg)


# # # # # # # # # # # # # # # # # # #
# fx: trap_observer
#     callback for when trap is received
# # # # # # # # # # # # # # # # # # #
def trap_observer(snmp_engine, execpoint, variables, cbCtx):
    """
    Decompose trap attributes and load in dictionary which is later used to 
    create json string for publishing to dmaap. 
    :Parameters:
      snmp_engine
         snmp engine created to listen for arriving traps
      execpoint
         point in code that trap_observer was invoked
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

    # empty dictionary on new trap
    trap_dict = {}

    # assign uuid to trap
    trap_dict["uuid"] = str(uuid_mod.uuid1())

    # ip and hostname
    ip_addr_str = str(variables['transportAddress'][0])
    trap_dict["agent address"] = ip_addr_str
    try:
       if int(dns_cache_ip_expires[ip_addr_str] < int(time.time())):
           dcae_logger.debug ('dns cache expired for %s' % ip_addr_str)
           raise Exception('cache expired for %s at %d - updating value' % (ip_addr_str, (dns_cache_ip_expires[ip_addr_str])))
       else:
           trap_dict["agent name"] = dns_cache_ip_to_name[ip_addr_str]
    except:
        dcae_logger.debug ('dns cache expired or missing for %s - reloading' % ip_addr_str)
        host_addr_info = socket.gethostbyaddr(ip_addr_str)
        agent_fqdn = str(host_addr_info[0])
        trap_dict["agent name"] = agent_fqdn

        dns_cache_ip_to_name[ip_addr_str] = agent_fqdn
        dns_cache_ip_expires[ip_addr_str] = (time.time() + yc_dns_cache_ttl_seconds)
        dcae_logger.debug ('cache for %s (%s) updated - set to expire at %d' % (agent_fqdn, ip_addr_str, dns_cache_ip_expires[ip_addr_str]))

        dns_cache_ip_to_name[str(trap_dict["agent address"])]

    trap_dict["cambria.partition"] = str(trap_dict["agent name"])
    trap_dict["community"] = ""    # do not include cleartext community in pub
    trap_dict["community len"] = 0    # do not include cleartext community in pub

    # FIXME.CHECK_WITH_DOWNSTREAM_CONSUMERS: get rid of round for millisecond val
    # epoch_second = int(round(time.time()))
    epoch_msecond = time.time()
    epoch_second = int(round(epoch_msecond))
    if epoch_second == last_epoch_second:
        traps_in_epoch +=1
    else:
        traps_in_epoch = 0
    last_epoch_second = epoch_second
    traps_in_epoch_04d = format(traps_in_epoch, '04d')
    # FIXME: get rid of exponential formatted output
    trap_dict['epoch_serno'] = (epoch_second * 10000) + traps_in_epoch
    # FIXME.PERFORMANCE: faster to use strings?
    # trap_dict['epoch_serno'] = (str(epoch_second) + str(traps_in_epoch_04d))
    
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
       trap_dict["security engine"] = str(variables['contextEngineId'].prettyPrint())
    trap_dict['time received'] = epoch_msecond
    trap_dict['trap category'] = "DCAE-COLLECTOR-UCSNMP" # get this from dmaap_url when ready

# Callback function for receiving notifications
# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def cbFun(snmp_engine, stateReference, contextEngineId, contextName,
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

    print('CB for notification from ContextEngineId "%s", ContextName "%s"' % (contextEngineId.prettyPrint(),
                                                                        contextName.prettyPrint()))
    # FIXME:  add conversion from v1 to v2 prior to below? or special handling for v1?
    # print('entering cbFun, trap_dict is: %s' % (json.dumps(trap_dict)))

    vb_dict = {}

    vb_idx=0;
    k1=""
    k2=""

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

    for name, val in varBinds:
        if vb_idx == 0:
            vb_sys_uptime_oid = name
            vb_sys_uptime = val
            # print('vb_sys_uptime = %s' % (vb_sys_uptime))
        else:
            if vb_idx == 1:
                trap_dict["notify OID"] = str(val)
                trap_dict["notify OID len"] = (trap_dict["notify OID"].count('.') + 1)
                # print('vb_notify_oid = %s' % (vb_notify_oid))
            # else:
                # vb_idx_02d = format((vb_idx - 2), '02d')
        vb_idx_02d = format((vb_idx), '02d')

        k1="varbind" + str(vb_idx_02d) + "_oid"
        k2="varbind" + str(vb_idx_02d) + "_val"
        vb_dict[k1] = name.prettyPrint()
        vb_dict[k2] = val.prettyPrint()
    
        vb_idx += 1

    # print('SNMP trap arrived: %s' % (pprint.pprint(json.dumps(trap_dict))))
    trap_dict["num varbinds"] = vb_idx

    # FIXME:  now add varbind dict to trap dict
    trap_dict["varbinds"] = vb_dict

    trap_json_msg = json.dumps(trap_dict)
    print('SNMP trap arrived: %s' % trap_json_msg)

    # FIXME: temporary pub to UEB for validating JSON
    post_ueb(trap_json_msg)


# # # # # # # # # # # # #
# Main  MAIN  Main  MAIN
# # # # # # # # # # # # #
# parse command line args
parser = argparse.ArgumentParser(description='Post SNMP traps ' \
                                             'to DCAE DMaap MR')
parser.add_argument('-c', action="store", dest="yaml_conf_file", type=str,
                    help="yaml config file name")
parser.add_argument('-u', action="store", dest="ueb_url", type=str,
                    help="ueb url for testing purposes ONLY")
parser.add_argument('-v', action="store_true", dest="verbose",
                    help="verbose logging")

# set vars from args
parser.set_defaults(yaml_conf_file = "")

# parse args
args = parser.parse_args()

# set vars from args
yaml_conf_file = args.yaml_conf_file
ueb_url = args.ueb_url
verbose = args.verbose

# Get non-ENV settings from config file; spoof 2 params
# so same fx can be used for signal handling
if yaml_conf_file == "":
   usage_err
else:
   load_cfg('0', '0')

# save current PID for future/external reference
pid_file_name = '%s/%s.pid' % (yc_pid_dir, prog_name)
save_pid(pid_file_name)

# setup custom logger
setup_dcae_logger()

# bump up logging level if overridden at command line
if verbose:
    dcae_logger.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
    dcae_logger.debug("log level increased to DEBUG")

dcae_logger.info("log will include info level messages")
dcae_logger.error("log will include error level messages")
dcae_logger.debug("log will include debug level messages")

# Get the event loop for this thread
loop = asyncio.get_event_loop()

# Create SNMP engine with autogenernated engineID and pre-bound
# to socket transport dispatcher
snmp_engine = engine.SnmpEngine()

# # # # # # # # # # # #
# Transport setup
# # # # # # # # # # # #

# UDP over IPv4, first listening interface/port
config.addTransport(
    snmp_engine,
    udp.domainName + (1,),
    udp.UdpTransport().openServerMode(('127.0.0.1', 6163))
)

# UDP over IPv4, second listening interface/port
config.addTransport(
    snmp_engine,
    udp.domainName + (2,),
    udp.UdpTransport().openServerMode(('127.0.0.1', 2162))
)

# # # # # # # # # # # #
# SNMPv1/2c setup
# # # # # # # # # # # #

# SecurityName <-> CommunityName mapping
config.addV1System(snmp_engine, 'my-area', 'public')

# register trap_observer for message arrival
snmp_engine.observer.registerObserver(
    trap_observer,
    'rfc3412.receiveMessage:request',
    'rfc3412.returnResponsePdu'
    # 'rfc2576.processIncomingMsg:writable'
)

# Register SNMP Application at the SNMP engine
ntfrcv.NotificationReceiver(snmp_engine, cbFun)

snmp_engine.transportDispatcher.jobStarted(1)  # this job would never finish

# Run I/O dispatcher which would receive queries and send confirmations
try:
    snmp_engine.transportDispatcher.runDispatcher()
except:
    snmp_engine.observer.unregisterObserver()
    snmp_engine.transportDispatcher.closeDispatcher()
    rm_pid(pid_file_name)
