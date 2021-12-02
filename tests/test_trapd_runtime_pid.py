# ============LICENSE_START=======================================================
# Copyright (c) 2019-2021 AT&T Intellectual Property. All rights reserved.
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
import trapd_runtime_pid
import trapd_io


class test_save_pid(unittest.TestCase):
    """
    Test the save_pid mod
    """

    def test_correct_usage(self):
        """
        Test that attempt to create pid file in standard location works
        """
        result = trapd_runtime_pid.save_pid("/tmp/snmptrap_test_pid_file")
        self.assertEqual(result, True)

    def test_missing_directory(self):
        """
        Test that attempt to create pid file in missing dir fails
        """
        result = trapd_runtime_pid.save_pid("/bogus/directory/for/snmptrap_test_pid_file")
        self.assertEqual(result, False)


class test_rm_pid(unittest.TestCase):
    """
    Test the rm_pid mod
    """

    def test_correct_usage(self):
        """
        Test that attempt to remove pid file in standard location works
        """
        # must create it before removing it
        result = trapd_runtime_pid.save_pid("/tmp/snmptrap_test_pid_file")
        self.assertEqual(result, True)
        result = trapd_runtime_pid.rm_pid("/tmp/snmptrap_test_pid_file")
        self.assertEqual(result, True)

    def test_missing_file(self):
        """
        Test that attempt to rm non-existent pid file fails
        """
        result = trapd_runtime_pid.rm_pid("/tmp/snmptrap_test_pid_file_9999")
        self.assertEqual(result, False)


if __name__ == "__main__":
    unittest.main()
