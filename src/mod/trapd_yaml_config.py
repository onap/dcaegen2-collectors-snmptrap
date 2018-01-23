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
Read the SNMP trap receiver YAML config file, which contains the vast
majority of configurable parameters for the process, including
location of other config files, http timeouts, dns cache times,
etc.
"""

__docformat__ = 'restructuredtext'

import os
import sys
import string
import time
import traceback
import collections
import yaml
from trapd_exit import cleanup_and_exit


prog_name = os.path.basename(__file__)


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# function: get_yaml_cfg
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def read_yaml_config(loc_yaml_conf_file):
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
      yaml config runtime protocol files dmaap
    :Variables:
      yc_transport
        protocol transport for snmp traps (udp|tcp)
      yc_ipv4_interface
        what ipv4 interface to listen for traps on
      yc_ipv4_port
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
      yc_trapd_diag
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
      yc_http_retries
        num of http retries to attempt in response to failed post
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

    # named tuple for values in yaml config file
    _yaml_config_values_nt = collections.namedtuple('yaml_config_values', ['yc_transport', 'yc_ipv4_port', 'yc_ipv4_interface', 'yc_ipv6_port', 'yc_ipv6_interface', 'yc_dns_cache_ttl_seconds', 'yc_runtime_base_dir', 'yc_log_dir', 'yc_data_dir', 'yc_pid_dir', 'yc_trap_conf', 'yc_trapd_diag',
                                                                           'yc_raw_traps_log', 'yc_published_traps_dir', 'yc_trap_stats_log', 'yc_perm_status_file', 'yc_dmaap_conf', 'yc_http_timeout', 'yc_http_retries', 'yc_http_secs_between_retries', 'yc_primary_publisher', 'yc_peer_publisher', 'yc_max_traps_between_publish', 'yc_max_milliseconds_between_publish'])

    with open(loc_yaml_conf_file, 'r') as yaml_fd:
        cfg_data = yaml.load(yaml_fd)

    # ONAP FIXME: split try into per-section except loops below
    try:
        # protocol
        yc_transport = (cfg_data['protocol']['transport'])
        yc_ipv4_interface = (cfg_data['protocol']['ipv4_interface'])
        yc_ipv4_port = int(cfg_data['protocol']['ipv4_port'])
        yc_ipv6_interface = (cfg_data['protocol']['ipv6_interface'])
        yc_ipv6_port = int(cfg_data['protocol']['ipv6_port'])
        yc_dns_cache_ttl_seconds = int(
            cfg_data['protocol']['dns_cache_ttl_seconds'])

        # files and directories
        yc_runtime_base_dir = (cfg_data['files']['runtime_base_dir'])
        yc_log_dir = (cfg_data['files']['log_dir'])
        yc_data_dir = (cfg_data['files']['data_dir'])
        yc_pid_dir = (cfg_data['files']['pid_dir'])
        yc_trap_conf = (cfg_data['files']['trap_conf'])
        yc_trapd_diag = (cfg_data['files']['snmptrapd_diag'])
        yc_raw_traps_log = (cfg_data['files']['raw_traps_log'])
        yc_published_traps_dir = (cfg_data['files']['published_traps_dir'])
        yc_trap_stats_log = (cfg_data['files']['trap_stats_log'])
        yc_perm_status_file = (cfg_data['files']['perm_status_file'])

        # dmaap
        yc_dmaap_conf = (cfg_data['dmaap']['dmaap_conf'])
        yc_http_timeout = (cfg_data['dmaap']['http_timeout'])
        yc_http_retries = (cfg_data['dmaap']['http_retries'])
        yc_http_secs_between_retries = (
            cfg_data['dmaap']['http_secs_between_retries'])
        yc_primary_publisher = (cfg_data['dmaap']['primary_publisher'])
        yc_peer_publisher = (cfg_data['dmaap']['peer_publisher'])
        yc_max_traps_between_publish = (
            cfg_data['dmaap']['max_traps_between_publish'])
        yc_max_milliseconds_between_publish = (
            cfg_data['dmaap']['max_milliseconds_between_publish'])

    except:
        print("ERROR reading config:    %s" % loc_yaml_conf_file)
        raise
        cleanup_and_exit(1, "undefined")

    # print back for confirmation
    print("Configs read from: %s" % loc_yaml_conf_file)
    print("    protocol section:")
    print("        transport: %s" % yc_transport)
    print("        ipv4_port: %s" % yc_ipv4_port)
    print("        ipv4_interface: %s" % yc_ipv4_interface)
    print("        ipv6_port: %s" % yc_ipv6_port)
    print("        ipv6_interface: %s" % yc_ipv6_interface)
    print("        dns_cache_ttl_seconds: %s" % yc_dns_cache_ttl_seconds)
    print("    files section:")
    print("        runtime_base_dir: %s" % yc_runtime_base_dir)
    print("        log_dir: %s" % yc_log_dir)
    print("        data_dir: %s" % yc_data_dir)
    print("        pid_dir: %s" % yc_pid_dir)
    print("        trap_conf: %s" % yc_trap_conf)
    print("        snmptrapd_diag: %s" % yc_trapd_diag)
    print("        raw_traps_log: %s" % yc_raw_traps_log)
    print("        published_traps_dir: %s" % yc_published_traps_dir)
    print("        trap_stats_log: %s" % yc_trap_stats_log)
    print("        perm_status_file: %s" % yc_perm_status_file)
    print("    dmaap section:")
    print("        dmaap_config_file: %s" % yc_dmaap_conf)
    print("        http_timeout: %s" % yc_http_timeout)
    print("        http_retries: %s" % yc_http_retries)
    print("        http_secs_between_retries: %s" %
          yc_http_secs_between_retries)
    print("        primary_publisher: %s" % yc_primary_publisher)
    print("        peer_publisher: %s" % yc_peer_publisher)
    print("        max_traps_between_publish: %s" %
          yc_max_traps_between_publish)
    print("        max_milliseconds_between_publish: %s" %
          yc_max_milliseconds_between_publish)

    _yaml_config_values = _yaml_config_values_nt(yc_transport=yc_transport, yc_ipv4_port=yc_ipv4_port, yc_ipv4_interface=yc_ipv4_interface, yc_ipv6_port=yc_ipv6_port, yc_ipv6_interface=yc_ipv6_interface, yc_dns_cache_ttl_seconds=yc_dns_cache_ttl_seconds, yc_runtime_base_dir=yc_runtime_base_dir, yc_log_dir=yc_log_dir, yc_data_dir=yc_data_dir, yc_pid_dir=yc_pid_dir, yc_trap_conf=yc_trap_conf, yc_trapd_diag=yc_trapd_diag, yc_raw_traps_log=yc_raw_traps_log, yc_published_traps_dir=yc_published_traps_dir,
                                                 yc_trap_stats_log=yc_trap_stats_log, yc_perm_status_file=yc_perm_status_file, yc_dmaap_conf=yc_dmaap_conf, yc_http_timeout=yc_http_timeout, yc_http_retries=yc_http_retries, yc_http_secs_between_retries=yc_http_secs_between_retries, yc_primary_publisher=yc_primary_publisher, yc_peer_publisher=yc_peer_publisher, yc_max_traps_between_publish=yc_max_traps_between_publish, yc_max_milliseconds_between_publish=yc_max_milliseconds_between_publish)

    return _yaml_config_values
