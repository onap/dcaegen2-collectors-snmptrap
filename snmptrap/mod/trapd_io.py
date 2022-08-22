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
        for fd, nm in [
            (tds.eelf_error_fd, "error"),
            (tds.eelf_debug_fd, "debug"),
            (tds.eelf_audit_fd, "eelf"),
            (tds.eelf_metrics_fd, "metrics"),
            (tds.arriving_traps_fd, "arriving_traps"),
            (tds.json_traps_fd, "json_traps"),
        ]:
            if fd is None:
                msg = "Error closing log file for " + nm
                stdout_logger(msg)
            else:
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
        msg = "Error opening json_log %s : %s" % (tds.json_traps_filename, str(e))
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    # arriving trap log
    roll_file(tds.arriving_traps_filename)

    try:
        tds.arriving_traps_fd = open_file(tds.arriving_traps_filename)
    except Exception as e:
        msg = "Error opening arriving traps %s : %s" % (tds.arriving_traps_filename, str(e))
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

        tds.eelf_error_file_name = tds.c_config["files"]["eelf_base_dir"] + "/" + tds.c_config["files"]["eelf_error"]
        tds.eelf_error_fd = open_file(tds.eelf_error_file_name)

    except Exception as e:
        # here if we cannot create the filename
        msg = "Error opening eelf error log : " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    try:
        tds.eelf_debug_file_name = tds.c_config["files"]["eelf_base_dir"] + "/" + tds.c_config["files"]["eelf_debug"]
        tds.eelf_debug_fd = open_file(tds.eelf_debug_file_name)

    except Exception as e:
        # here if we cannot create the filename
        msg = "Error opening eelf debug log : " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    try:
        tds.eelf_audit_file_name = tds.c_config["files"]["eelf_base_dir"] + "/" + tds.c_config["files"]["eelf_audit"]
        tds.eelf_audit_fd = open_file(tds.eelf_audit_file_name)
    except Exception as e:
        # here if we cannot create the filename
        msg = "Error opening eelf audit log : " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)

    try:
        tds.eelf_metrics_file_name = (
            tds.c_config["files"]["eelf_base_dir"] + "/" + tds.c_config["files"]["eelf_metrics"]
        )
        tds.eelf_metrics_fd = open_file(tds.eelf_metrics_file_name)
    except Exception as e:
        # here if we cannot create the filename
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

    _file_name_suffix = "%s" % (
        datetime.datetime.fromtimestamp(time.time()).fromtimestamp(time.time()).strftime("%Y-%m-%dT%H:%M:%S")
    )

    _loc_file_name_bak = _loc_file_name + "." + _file_name_suffix

    # roll existing file if present
    if os.path.isfile(_loc_file_name):
        try:
            os.rename(_loc_file_name, _loc_file_name_bak)
            return True
        except Exception as e:
            _msg = "ERROR: Unable to rename %s to %s" % (_loc_file_name, _loc_file_name_bak)
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_ERROR, tds.CODE_GENERAL, _msg)
            return False

    return False


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
        _loc_fd = open(_loc_file_name, "a", 1)
        return _loc_fd
    except Exception as e:
        msg = "Error opening " + _loc_file_name + " append mode - " + str(e)
        stdout_logger(msg)
        cleanup_and_exit(1, tds.pid_file_name)


# # # # # # # # # # # # #
# fx: close_file
# # # # # # # # # # # # #


def close_file(_loc_fd, _loc_filename):
    """  close _loc_file_name, return True with success, False otherwise """

    try:
        _loc_fd.close()
        return True
    except Exception as e:
        msg = "Error closing %s : %s - results indeterminate" % (_loc_filename, str(e))
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_FATAL, tds.CODE_GENERAL, msg)
        return False


# # # # # # # # # # # # # # # # # # #
# fx: ecomp_logger -> log in eelf format until standard
#     is released for python via LOG-161
# # # # # # # # # # ## # # # # # # #


def ecomp_logger(_log_type, _sev, _error_code, _msg):
    """
    Log to ecomp-style logfiles.  Logs include:

    Note:  this will be updated when https://jira.onap.org/browse/LOG-161
    is closed/available; until then, we resort to a generic format with
    valuable info in "extra=" field (?)

    :Parameters:
       _msg -
    :Exceptions:
       none
    :Keywords:
       eelf logging
    :Log Styles:

       :error.log:

       if CommonLogger.verbose: print("using CommonLogger.ErrorFile")
          self._logger.log(50, '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
          % (requestID, threadID, serviceName, partnerName, targetEntity, targetServiceName,
             errorCategory, errorCode, errorDescription, detailMessage))

       error.log example:

       2018-02-20T07:21:34,007+00:00||MainThread|snmp_log_monitor||||FATAL|900||Tue Feb 20 07:21:11 UTC 2018 CRITICAL: [a0cae74e-160e-11e8-8f9f-0242ac110002] ALL publish attempts failed to DMAPP server: dcae-mrtr-zltcrdm5bdce1.1dff83.rdm5b.tci.att.com, topic: DCAE-COLLECTOR-UCSNMP, 339 trap(s) not published in epoch_serno range: 15191112530000 - 15191112620010

       :debug.log:

       if CommonLogger.verbose: print("using CommonLogger.DebugFile")
          self._logger.log(50, '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
          % (requestID, threadID, serverName, serviceName, instanceUUID, upperLogLevel,
          severity, serverIPAddress, server, IPAddress, className, timer, detailMessage))

       debug.log example:

         none available

       :audit.log:

       if CommonLogger.verbose: print("using CommonLogger.AuditFile")
       endAuditTime, endAuditMsec = self._getTime()
       if self._begTime is not None:
          d = {'begtime': self._begTime, 'begmsecs': self._begMsec, 'endtime': endAuditTime,
               'endmsecs': endAuditMsec}
       else:
          d = {'begtime': endAuditTime, 'begmsecs': endAuditMsec, 'endtime': endAuditTime,
               'endmsecs': endAuditMsec}

       self._logger.log(50, '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
       % (requestID, serviceInstanceID, threadID, serverName, serviceName, partnerName,
       statusCode, responseCode, responseDescription, instanceUUID, upperLogLevel,
       severity, serverIPAddress, timer, server, IPAddress, className, unused,
       processKey, customField1, customField2, customField3, customField4,
       detailMessage), extra=d)


       :metrics.log:

          self._logger.log(50,'%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
          % (requestID, serviceInstanceID, threadID, serverName, serviceName, partnerName,
          targetEntity, targetServiceName, statusCode, responseCode, responseDescription,
          instanceUUID, upperLogLevel, severity, serverIPAddress, timer, server,
          IPAddress,
          className, unused, processKey, targetVirtualEntity, customField1, customField2,
          customField3, customField4, detailMessage), extra=d)

       metrics.log example:

          none available


    """

    unused = ""

    # new requirement to send all logs to stdout
    log_to_stdout = True

    # above were various attempts at setting time string found in other
    # libs; instead, let's keep it real:
    t_out = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    calling_fx = inspect.stack()[1][3]

    # DLFM: this entire module is a xyz to override concept of prog logging
    #        written across multiple files (???), making diagnostics IMPOSSIBLE!
    #        Hoping to leverage ONAP logging libraries & standards when available

    # catch invalid log type
    if _log_type < 1 or _log_type > 5:
        msg = "INVALID log type: %s " % _log_type
        _out_rec = "%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
            calling_fx,
            "snmptrapd",
            unused,
            unused,
            unused,
            tds.SEV_TYPES[_sev],
            _error_code,
            unused,
            (msg + _msg),
        )
        try:
            tds.eelf_error_fd.write("%s|%s\n" % (t_out, str(_out_rec)))
            if log_to_stdout:
                print("%s|%s" % (t_out, str(_out_rec)))
        except Exception as e:
            stdout_logger(str(_out_rec))

        return False

    if _sev >= tds.minimum_severity_to_log:
        # log to appropriate eelf log (different files ??)
        if _log_type == tds.LOG_TYPE_ERROR:
            # _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s'
            # _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s'
            #            % (calling_fx, "snmptrapd", unused, unused, unused, tds.SEV_TYPES[_sev], _error_code, unused, _msg))
            _out_rec = "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                unused,
                unused,
                calling_fx,
                unused,
                "snmptrapd",
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                tds.SEV_TYPES[_sev],
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                unused,
                _msg,
            )
            try:
                tds.eelf_error_fd.write("%s|%s|%s\n" % (t_out, t_out, str(_out_rec)))
                if log_to_stdout:
                    print("%s|%s|%s" % (t_out, t_out, str(_out_rec)))
            except Exception as e:
                stdout_logger(str(_out_rec))
        elif _log_type == tds.LOG_TYPE_AUDIT:
            # log message in AUDIT format
            # _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s'
            #             % (calling_fx, "snmptrapd", unused, unused, unused, tds.SEV_TYPES[_sev], _error_code, unused, _msg))
            _out_rec = "%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                calling_fx,
                "snmptrapd",
                unused,
                unused,
                unused,
                tds.SEV_TYPES[_sev],
                _error_code,
                unused,
                _msg,
            )
            try:
                tds.eelf_audit_fd.write("%s|%s\n" % (t_out, str(_out_rec)))
                if log_to_stdout:
                    print("%s|%s" % (t_out, str(_out_rec)))
            except Exception as e:
                stdout_logger(str(_out_rec))
        elif _log_type == tds.LOG_TYPE_METRICS:
            # log message in METRICS format
            _out_rec = "%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
                calling_fx,
                "snmptrapd",
                unused,
                unused,
                unused,
                tds.SEV_TYPES[_sev],
                _error_code,
                unused,
                _msg,
            )
            try:
                tds.eelf_metrics_fd.write("%s|%s\n" % (t_out, str(_out_rec)))
                if log_to_stdout:
                    print("%s|%s" % (t_out, str(_out_rec)))
            except Exception as e:
                stdout_logger(str(_out_rec))

        # DEBUG *AND* others - there *MUST BE* a single time-sequenced log for diagnostics!
        # DLFM: too much I/O !!!
        # always write to debug; we need ONE logfile that has time-sequence full view !!!
        # log message in DEBUG format
        _out_rec = "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
            unused,
            calling_fx,
            "snmptrapd",
            unused,
            unused,
            unused,
            tds.SEV_TYPES[_sev],
            _error_code,
            unused,
            _msg,
        )
        try:
            tds.eelf_debug_fd.write("%s|%s\n" % (t_out, str(_out_rec)))
            if log_to_stdout:
                print("%s|%s" % (t_out, str(_out_rec)))
        except Exception as e:
            stdout_logger(str(_out_rec))

    return True


# # # # # # # # # # # # #
# fx: stdout_logger
# # # # # # # # # # # # #


def stdout_logger(_msg):
    """
    Log info/errors to stdout.  This is done:
      - for critical runtime issues

    :Parameters:
      _msg
         message to print
    :Exceptions:
      none
    :Keywords:
      log stdout
    :Variables:
    """

    t_out = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S,%f")[:-3]

    print("%s %s" % (t_out, _msg))
