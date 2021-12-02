# ============LICENSE_START=======================================================
# Copyright (c) 2018-2021 AT&T Intellectual Property. All rights reserved.
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

import pytest
import unittest
import trapd_exit

pid_file = "/tmp/test_pid_file"
pid_file_dne = "/tmp/test_pid_file_NOT"


class test_cleanup_and_exit(unittest.TestCase):
    """
    Test the cleanup_and_exit mod
    """

    def test_normal_exit(self):
        """
        Test normal exit works as expected
        """
        open(pid_file, "w")

        with pytest.raises(SystemExit) as pytest_wrapped_sys_exit:
            result = trapd_exit.cleanup_and_exit(0, pid_file)
            assert pytest_wrapped_sys_exit.type == SystemExit
            assert pytest_wrapped_sys_exit.value.code == 0

        # compare = str(result).startswith("SystemExit: 0")
        # self.assertEqual(compare, True)

    def test_abnormal_exit(self):
        """
        Test exit with missing PID file exits non-zero
        """
        with pytest.raises(SystemExit) as pytest_wrapped_sys_exit:
            result = trapd_exit.cleanup_and_exit(0, pid_file_dne)
            assert pytest_wrapped_sys_exit.type == SystemExit
            assert pytest_wrapped_sys_exit.value.code == 1


if __name__ == "__main__":
    unittest.main()
