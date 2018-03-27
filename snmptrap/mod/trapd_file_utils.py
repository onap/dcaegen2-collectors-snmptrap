# ============LICENSE_START=======================================================)
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
"""

__docformat__ = 'restructuredtext'

# basics
import datetime
import errno
import inspect
import json
import logging
import logging.handlers
import os
import sys
import string
import time
import traceback
import unicodedata

# dcae_snmptrap
import trapd_settings as tds
from trapd_logging import ecomp_logger, stdout_logger
from trapd_exit import cleanup_and_exit

prog_name = os.path.basename(__file__)


# # # # # # # # # # # # # # # # # # #
# fx: roll_all_logs -> roll all logs to timestamped backup
# # # # # # # # # # ## # # # # # # #


def roll_all_logs():
    """
    roll all active logs to timestamped version, open new one
    based on frequency defined in files.roll_frequency
    """

    # first roll all the eelf files
    # NOTE:  this will go away when onap logging is standardized/available
    try:
        # open various ecomp logs - if any fails, exit
        for fd in [tds.eelf_error_fd, tds.eelf_debug_fd, tds.eelf_audit_fd,
                   tds.eelf_metrics_fd, tds.arriving_traps_fd, tds.json_traps_fd]:
            fd.close()

        roll_file(tds.eelf_error_file_name)
        roll_file(tds.eelf_debug_file_name)
        roll_file(tds.eelf_audit_file_name)
        roll_file(tds.eelf_metrics_file_name)

    except Exception as e:
        msg = "Error closing logs: " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    reopened_successfully = open_eelf_logs()
    if not reopened_successfully:
        msg = "Error re-opening EELF logs during roll-over to timestamped versions - EXITING"
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    # json log
    roll_file(tds.json_traps_filename)

    try:
        tds.json_traps_fd = open_file(tds.json_traps_filename)
    except Exception as e:
        msg = ("Error opening json_log %s : %s" %
               (json_traps_filename, str(e)))
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    # arriving trap log
    roll_file(tds.arriving_traps_filename)

    try:
        tds.arriving_traps_fd = open_file(tds.arriving_traps_filename)
    except Exception as e:
        msg = ("Error opening arriving traps %s : %s" %
               (arriving_traps_filename, str(e)))
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)


# # # # # # # # # # # # # # # # # # #
# fx: setup_ecomp_logs -> log in eelf format until standard
#     is released for python via LOG-161
# # # # # # # # # # ## # # # # # # #


def open_eelf_logs():
    """
    open various (multiple ???) logs
    """

    try:
        # open various ecomp logs - if any fails, exit

        tds.eelf_error_file_name = (
            tds.c_config['files.eelf_base_dir'] + "/" + tds.c_config['files.eelf_error'])
        tds.eelf_error_fd = open_file(tds.eelf_error_file_name)

    except Exception as e:
        msg = "Error opening eelf error log : " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    try:
        tds.eelf_debug_file_name = (
            tds.c_config['files.eelf_base_dir'] + "/" + tds.c_config['files.eelf_debug'])
        tds.eelf_debug_fd = open_file(tds.eelf_debug_file_name)

    except Exception as e:
        msg = "Error opening eelf debug log : " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    try:
        tds.eelf_audit_file_name = (
            tds.c_config['files.eelf_base_dir'] + "/" + tds.c_config['files.eelf_audit'])
        tds.eelf_audit_fd = open_file(tds.eelf_audit_file_name)
    except Exception as e:
        msg = "Error opening eelf audit log : " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    try:
        tds.eelf_metrics_file_name = (
            tds.c_config['files.eelf_base_dir'] + "/" + tds.c_config['files.eelf_metrics'])
        tds.eelf_metrics_fd = open_file(tds.eelf_metrics_file_name)
    except Exception as e:
        msg = "Error opening eelf metric log : " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    return True

# # # # # # # # # # # # # # # # # # #
# fx: roll_log_file -> move provided filename to timestamped version
# # # # # # # # # # ## # # # # # # #


def roll_file(_loc_file_name):
    """
    move active file to timestamped archive
    """

    _file_name_suffix = "%s" % (datetime.datetime.fromtimestamp(time.time()).
                                fromtimestamp(time.time()).
                                strftime('%Y-%m-%dT%H:%M:%S'))

    _loc_file_name_bak = _loc_file_name + '.' + _file_name_suffix

    # roll existing file if present
    if os.path.isfile(_loc_file_name):
        try:
            os.rename(_loc_file_name, _loc_file_name_bak)
        except Exception as e:
            _msg = ("ERROR: Unable to rename %s to %s"
                    % (_loc_file_name,
                       _loc_file_name_bak))
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_CRIT,
                         tds.CODE_GENERAL, _msg)


# # # # # # # # # # # # #
# fx: open_log_file
# # # # # # # # # # # # #


def open_file(_loc_file_name):
    """
    open _loc_file_name, return file handle
    """

    try:
        # open append mode just in case so nothing is lost, but should be
        # non-existent file
        _loc_fd = open(_loc_file_name, 'a')
        return _loc_fd
    except Exception as e:
        msg = "Error opening " + _loc_file_name + " append mode - " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)


# # # # # # # # # # # # #
# fx: close_file
# # # # # # # # # # # # #
    """
    close _loc_file_name, return True with success, False otherwise
    """


def close_file(_loc_fd, _loc_filename):

    try:
        _loc_fd.close()
        return True
    except Exception as e:
        msg = "Error closing %s : %s - results indeterminate" % (
            _loc_filename, str(e))
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_FATAL, tds.CODE_GENERAL, msg)
        return False
