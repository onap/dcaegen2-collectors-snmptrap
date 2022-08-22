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
"""

__docformat__ = "restructuredtext"


def init():

    # <CONSUL config cache>
    # consul config or simulated via json file
    global c_config
    c_config = None
    # </CONSUL config cache>

    # <DNS cache>
    #
    #     dns_cache_ip_to_name
    #        key [ip address] -> fqdn
    #     dns_cache_ip_expires
    #        key [ip address] -> epoch time this entry expires and must
    #        be reloaded
    global dns_cache_ip_to_name
    dns_cache_ip_to_name = {}
    global dns_cache_ip_expires
    dns_cache_ip_expires = {}
    # </DNS cache>

    # <EELF logs>
    global eelf_error_file_name
    eelf_error_file_name = ""
    global eelf_error_fd
    eelf_error_fd = None

    global eelf_debug_file_name
    eelf_debug_file_name = ""
    global eelf_debug_fd
    eelf_debug_fd = None

    global eelf_audit_file_name
    eelf_audit_file_name = ""
    global eelf_audit_fd
    eelf_audit_fd = None

    global eelf_metrics_file_name
    eelf_metrics_file_name = ""
    global eelf_metrics_fd
    eelf_metrics_fd = None

    global last_minute
    last_minute = 0
    global last_hour
    last_hour = 0
    global last_day
    last_day = 0
    # </EELF logs>

    # <trap dictionary and corresponding strings for publish
    global first_trap
    first_trap = True
    global first_varbind
    first_varbind = True
    global trap_dict
    trap_dict = {}
    global all_traps_json_str
    all_traps_json_str = ""
    global all_vb_json_str
    all_vb_json_str = ""
    global all_vb_str
    all_vb_str = ""
    global trap_uuids_in_buffer
    trap_uuids_in_buffer = ""
    # </trap and varbind dictionaries>

    # <publish timers and counters>
    global traps_in_minute
    traps_in_minute = 0
    global last_epoch_second
    last_epoch_second = 0
    global traps_since_last_publish
    traps_since_last_publish = 0
    global last_pub_time
    last_pub_time = 0
    global milliseconds_since_last_publish
    milliseconds_since_last_publish = 0
    global timeout_seconds
    timeout_seconds = 1.5
    global seconds_between_retries
    seconds_between_retries = 2
    global publisher_retries
    publisher_retries = 2
    # </publish timers and counters>

    # <publish http request session (persistent as much as possible)>
    global http_requ_session
    http_requ_session = None
    # </publish http request session>

    # <json log of traps published>
    global json_traps_filename
    json_traps_filename = ""
    global json_traps_fd
    json_traps_fd = None
    # </json log of traps published>

    # <log of arriving traps >
    global arriving_traps_filename
    arriving_traps_filename = ""
    global arriving_traps_fd
    arriving_traps_fd = None
    # <log of arriving traps >

    # <runtime PID>
    global pid_file_name
    pid_file_name = ""

    # <stormwatch>
    global sw_participant_oid_dict
    sw_participant_oid_dict = {}

    global sw_count_dict
    sw_count_dict = {}

    # </stormwatch >

    # <logging types and severities>
    global LOG_TYPES
    global LOG_TYPE_NONE
    global LOG_TYPE_ERROR
    global LOG_TYPE_DEBUG
    global LOG_TYPE_AUDIT
    global LOG_TYPE_METRICS
    LOG_TYPES = ["none", "ERROR", "DEBUG", "AUDIT", "METRICS"]
    LOG_TYPE_NONE = 0
    LOG_TYPE_ERROR = 1
    LOG_TYPE_DEBUG = 2
    LOG_TYPE_AUDIT = 3
    LOG_TYPE_METRICS = 4

    global SEV_TYPES
    global SEV_NONE
    global SEV_DETAILED
    global SEV_INFO
    global SEV_WARN
    global SEV_ERROR
    global SEV_FATAL
    SEV_TYPES = ["none", "DETAILED", "INFO", "WARN", "ERROR", "FATAL"]
    SEV_NONE = 0
    SEV_DETAILED = 1
    SEV_INFO = 2
    SEV_WARN = 3
    SEV_ERROR = 4
    SEV_FATAL = 5

    global CODE_GENERAL
    CODE_GENERAL = "100"

    global minimum_severity_to_log
    minimum_severity_to_log = 3

    # </logging types and severities>
