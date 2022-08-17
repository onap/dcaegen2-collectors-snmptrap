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
        Test normal exit works as expected, and exits with the 1st arg
        """
        # create an empty pid file
        with open(pid_file, "w"):
            pass

        with self.assertRaises(SystemExit) as exc:
            result = trapd_exit.cleanup_and_exit(0, pid_file)
        self.assertEqual(str(exc.exception), "0")


    def test_abnormal_exit(self):
        """
        Test exit with missing PID file. Still exits with the 1st arg.
        """

        with self.assertRaises(SystemExit) as exc:
            result = trapd_exit.cleanup_and_exit(0, pid_file_dne)
        self.assertEqual(str(exc.exception), "0")


if __name__ == "__main__": # pragma: no cover
    unittest.main()
