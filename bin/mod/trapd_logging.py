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
from trapd_exit import cleanup_and_exit

prog_name = os.path.basename(__file__)

current_min_sev_log_level = 2

CODE_GENERAL="100"   # 0

eelf_error_fd = None
eelf_debug_fd = None
eelf_audit_fd = None
eelf_metrics_fd = None


# FIXME: should come from CBS
service_name = "snmptrapd" 

# # # # # # # # # # # # # # # # # # #
# fx: roll_log_file -> move provided filename to timestamped version
# # # # # # # # # # ## # # # # # # #


def roll_log_file(_loc_file_name):
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
        except:
            _msg = ("ERROR: Unable to rename %s to %s"
                                % (_loc_file_name,
                                   _loc_file_name_bak))
            ecomp_logger(LOG_TYPE_ERROR, SEV_CRIT, CODE_GENERAL, _msg)

 
# # # # # # # # # # # # # # # # # # #
# fx: setup_ecomp_logs -> log in eelf format until standard 
#     is released for python via LOG-161
# # # # # # # # # # ## # # # # # # #


def eelf_log_open(_c_config):
    """
    manage ecomp logs 
    """

    global eelf_error_fd, eelf_debug_fd, eelf_audit_fd, eelf_metrics_fd 

    # now open an empty one
    try:
        # open various ecomp logs

        roll_log_file(_c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_error'])
        eelf_error_fd = open((_c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_error']),'w')

        roll_log_file(_c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_debug'])
        eelf_debug_fd = open((_c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_debug']),'w')

        roll_log_file(_c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_audit'])
        eelf_audit_fd = open((_c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_audit']),'w')

        roll_log_file(_c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_metrics'])
        eelf_metrics_fd = open((_c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_metrics']),'w')

    except Exception as e:
        msg = "Error opening eelf logs " + str(e)
        stdout_logger(msg)
        sys.exit(1)


# # # # # # # # # # # # # # # # # # #
# fx: ecomp_logger -> log in eelf format until standard 
#     is released for python via LOG-161
# # # # # # # # # # ## # # # # # # #

def ecomp_logger(_c_config, _log_type, _sev, _error_code, _msg):
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

    global eelf_error_fd, eelf_debug_fd, eelf_audit_fd, eelf_metrics_fd , current_min_sev_log_level, service_name

    unused = ""

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
    
    # ct = time.time()
    # lt = time.localtime(ct)
    # t_hman = time.strftime(DateFmt, lt)
    # t_ms = (ct - int(ct)) * 1000
    # above were various attempts at setting time string found in other
    # libs; instead, let's keep it real:
    t_out = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S,%f")[:-3]
    calling_fx = inspect.stack()[1][3]

    # FIXME: this entire module is a hack to override concept of prog logging 
    #        written across multiple files (???), making diagnostics IMPOSSIBLE!  
    #        Hoping to leverage ONAP logging libraries & standards when available
    # FIXME: ^2  These files grow WITHOUT BOUNDS.  MUST BE CHANGED BEFORE 
    #        FINAL CODE RELEASE

    if _log_type < 1 or _log_type > 5: 
        msg = ("INVALID log type: %s " % _log_type )
        _out_rec = ("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" \
        % ((t_out, calling_fx, service_name, unused, unused, unused, SEV_TYPES[_sev], _error_code, unused, (msg + _msg))))
        eelf_error_fd.write('%s\n' % str(_out_rec))
        return False

    if _log_type == LOG_TYPE_ERROR:
        # if file needs to be rolled, do it now
        # _log_file_name = _c_config['files']['eelf_base_dir'] + "/" + _c_config['files']['eelf_debug']
        # if os.stat(_log_file_name).st_size > 1024000:
        #     roll_log_file(_log_file_name)
        # log message in ERROR format
        _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
        % ((t_out, calling_fx, service_name, unused, unused, unused, SEV_TYPES[_sev], _error_code, unused, _msg)))
        eelf_error_fd.write('%s\n' % str(_out_rec))
    elif _log_type == LOG_TYPE_AUDIT:
        # log message in AUDIT format
        _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
        % ((t_out, calling_fx, service_name, unused, unused, unused, SEV_TYPES[_sev], _error_code, unused, _msg)))
        eelf_audit_fd.write('%s\n' % str(_out_rec))
    elif _log_type == LOG_TYPE_METRICS:
        # log message in METRICS format
        _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
        % ((t_out, calling_fx, service_name, unused, unused, unused, SEV_TYPES[_sev], _error_code, unused, _msg)))
        eelf_metrics_fd.write('%s\n' % str(_out_rec))

    # DEBUG *AND* others - there *MUST BE* a single time-sequenced log for diagnostics!
    # FIXME: too much I/O !!!
    # always write to debug; we need ONE logfile that has time-sequence full view !!!???
    if (_log_type == LOG_TYPE_DEBUG and _sev >= current_min_sev_log_level) or (_log_type != LOG_TYPE_DEBUG):
        # log message in DEBUG format
        _out_rec = ("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" \
        % ((t_out, calling_fx, service_name, unused, unused, unused, SEV_TYPES[_sev], _error_code, unused, _msg)))
        eelf_debug_fd.write('%s\n' % str(_out_rec))

# # # # # # # # # # # # #
# fx: stdout_logger
# # # # # # # # # # # # #


def stdout_logger(_msg):
    """
    Log info/errors to stdout.  This is done:
      - when verbose flag (-v) is present
      or
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
    # calling_fx = inspect.stack()[1][3]

    print('%s %s' % ( t_out, _msg))
