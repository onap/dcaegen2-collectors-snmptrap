# ============LICENSE_START=======================================================
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
trapd_perm_status maintains a 'permanent' status file
important messages for audit/diagnostics/etc
"""

__docformat__ = 'restructuredtext'

import logging
import os
import string
import time
import traceback

prog_name = os.path.basename(__file__)


# # # # # # # # # # # # #
# fx: log_to_perm_status
# # # # # # # # # # # # #
def log_to_perm_status(_loc_perm_file, _loc_perm_msg, _dcae_logger):
    """
    Log select errors too permanent logfile
    access.
    :Parameters:
      log message, logger
    :Exceptions:
      file open
        this function will catch exception of unable to
        open the log file
    :Keywords:
      permstatus
    """

    perm_fmt_date = time.strftime("%a %b %d %H:%M:%S %Z %Y")

    try:
        f = open(_loc_perm_file, 'a')
        f.write("%s %s\n" % (perm_fmt_date, _loc_perm_msg))
        f.close()
    except IOError:
        _dcae_logger.exception("File I/O Exception on %s" % perm_status_fd)
