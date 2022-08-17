# ============LICENSE_START=======================================================
# Copyright (c) 2017-2022 AT&T Intellectual Property. All rights reserved.
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
trapd_runtime_pid maintains a 'PID file' (file that contains the
PID of currently running trap receiver)
"""

__docformat__ = "restructuredtext"

import logging
import os
import string
import time
import traceback

prog_name = os.path.basename(__file__)


# # # # # # # # # # # # #
# fx: save_pid - save PID of running process
# # # # # # # # # # # # #
def save_pid(_pid_file_name):
    """
    Save the current process ID in a file for external
    access.
    :Parameters:
      none
    :Exceptions:
      file open
        this function will catch exception of unable to
        open/create _pid_file_name
    :Keywords:
      pid /var/run
    """

    try:
        pid_fd = open(_pid_file_name, "w")
        pid_fd.write("%d" % os.getpid())
        pid_fd.close()
    except IOError:
        print("IOError saving PID file %s :" % _pid_file_name)
        return False
    else:
        return True


# # # # # # # # # # # # #
# fx: rm_pid - remove PID of running process
# # # # # # # # # # # # #
def rm_pid(_pid_file_name):
    """
    Remove the current process ID file before exiting.
    :Parameters:
      none
    :Exceptions:
      file open
        this function will catch exception of unable to find or remove
        _pid_file_name
    :Keywords:
      pid /var/run
    """
    try:
        if os.path.isfile(_pid_file_name):
            os.remove(_pid_file_name)
            return True
        else:
            return False

    except:
        print("Error removing Runtime PID file:    %s" % _pid_file_name)
        return False
