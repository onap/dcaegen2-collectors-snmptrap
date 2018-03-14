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

import trapd_settings as tds

prog_name = os.path.basename(__file__)


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

    # catch invalid log type
    if _log_type < 1 or _log_type > 5: 
        msg = ("INVALID log type: %s " % _log_type )
        _out_rec = ("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" \
        % ((t_out, calling_fx, "snmptrapd", unused, unused, unused, tds.SEV_TYPES[_sev], _error_code, unused, (msg + _msg))))
        tds.eelf_error_fd.write('%s\n' % str(_out_rec))
        return False

    if _sev >= tds.minimum_severity_to_log:
        # log to appropriate eelf log (different files ??)
        if _log_type == tds.LOG_TYPE_ERROR:
            _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
            % ((t_out, calling_fx, "snmptrapd", unused, unused, unused, tds.SEV_TYPES[_sev], _error_code, unused, _msg)))
            tds.eelf_error_fd.write('%s\n' % str(_out_rec))
        elif _log_type == tds.LOG_TYPE_AUDIT:
            # log message in AUDIT format
            _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
            % ((t_out, calling_fx, "snmptrapd", unused, unused, unused, tds.SEV_TYPES[_sev], _error_code, unused, _msg)))
            tds.eelf_audit_fd.write('%s\n' % str(_out_rec))
        elif _log_type == tds.LOG_TYPE_METRICS:
            # log message in METRICS format
            _out_rec = ('%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
            % ((t_out, calling_fx, "snmptrapd", unused, unused, unused, tds.SEV_TYPES[_sev], _error_code, unused, _msg)))
            tds.eelf_metrics_fd.write('%s\n' % str(_out_rec))
    
        # DEBUG *AND* others - there *MUST BE* a single time-sequenced log for diagnostics!
        # FIXME: too much I/O !!!
        # always write to debug; we need ONE logfile that has time-sequence full view !!!
        # if (_log_type == tds.LOG_TYPE_DEBUG and _sev >= tds.current_min_sev_log_level) or (_log_type != tds.LOG_TYPE_DEBUG):
        
        # log message in DEBUG format
        _out_rec = ("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s" \
        % ((t_out, calling_fx, "snmptrapd", unused, unused, unused, tds.SEV_TYPES[_sev], _error_code, unused, _msg)))
        tds.eelf_debug_fd.write('%s\n' % str(_out_rec))

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
    # calling_fx = inspect.stack()[1][3]

    print('%s %s' % ( t_out, _msg))
