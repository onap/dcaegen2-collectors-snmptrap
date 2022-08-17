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
trapc_exit_snmptrapd is responsible for removing any existing runtime PID
file, and exiting with the provided (param 1) exit code
"""

__docformat__ = "restructuredtext"

import sys
import os
import string
from trapd_runtime_pid import save_pid, rm_pid

prog_name = os.path.basename(__file__)


# # # # # # # # # # # # #
# fx: cleanup_and_exit
#      - remove pid file
#      - exit with supplied return code
# # # # # # # # # # # # #
def cleanup_and_exit(_loc_exit_code, _pid_file_name):
    """
    Remove existing PID file, and exit with provided exit code
    :Parameters:
      _loc_exit_code
        value to return to calling shell upon exit
      _pid_file_name
        name of file that contains current process ID (for
        removal)
    :Exceptions:
      none
    :Keywords:
      runtime PID exit
    """

    if _pid_file_name is not None:
        rc = rm_pid(_pid_file_name)
    sys.exit(_loc_exit_code)
