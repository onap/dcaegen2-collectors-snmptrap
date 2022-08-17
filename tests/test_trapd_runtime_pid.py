# ============LICENSE_START=======================================================
# Copyright (c) 2019-2022 AT&T Intellectual Property. All rights reserved.
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

import os
import unittest
from unittest.mock import patch

import trapd_io
import trapd_runtime_pid


class test_trapd_runtime_pid(unittest.TestCase):
    """
    Test the save_pid mod
    """

    GOOD_PID_FILE = "/tmp/snmptrap_test_pid_file"
    BAD_PID_FILE = "/tmp/snmptrap_test_pid_file_not_there"

    def test_correct_usage(self):
        """
        Test that attempt to create pid file in standard location works
        """
        result = trapd_runtime_pid.save_pid(test_trapd_runtime_pid.GOOD_PID_FILE)
        self.assertEqual(result, True)


    def test_missing_directory(self):
        """
        Test that attempt to create pid file in missing dir fails
        """
        result = trapd_runtime_pid.save_pid("/bogus/directory/for/snmptrap_test_pid_file")
        self.assertEqual(result, False)


    """
    Test the rm_pid mod
    """

    def test_correct_usage(self):
        """
        Test that attempt to remove pid file in standard location works
        """
        # must create it before removing it
        self.assertTrue(trapd_runtime_pid.save_pid(test_trapd_runtime_pid.GOOD_PID_FILE))
        self.assertTrue(trapd_runtime_pid.rm_pid(test_trapd_runtime_pid.GOOD_PID_FILE))


    def test_missing_file(self):
        """
        Test that attempt to rm non-existent pid file fails
        """
        self.assertFalse(trapd_runtime_pid.rm_pid(test_trapd_runtime_pid.BAD_PID_FILE))


    def test_correct_usage_but_throws(self):
        """
        Test that an exception while removing returns false
        """
        self.assertTrue(trapd_runtime_pid.save_pid(test_trapd_runtime_pid.GOOD_PID_FILE))
        with patch('os.remove') as mock_remove:
            mock_remove.side_effect = RuntimeError("os.remove throws")
            self.assertFalse(trapd_runtime_pid.rm_pid(test_trapd_runtime_pid.GOOD_PID_FILE))


if __name__ == "__main__": # pragma: no cover
    unittest.main()
