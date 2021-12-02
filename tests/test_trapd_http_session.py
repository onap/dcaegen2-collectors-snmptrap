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
import trapd_http_session


class test_init_session_obj(unittest.TestCase):
    """
    Test the init_session_obj mod
    """

    def close_nonexisting_session(self):
        """
        test close of existing http session
        """
        sess = "no session"
        result = trapd_http_session.close_session_obj(sess)
        self.assertEqual(result, True)

    def init_session(self):
        """
        test creation of http session
        """
        result = trapd_http_session.init_session_obj()
        compare = str(result).startswith("<requests.sessions.Session object at")
        self.assertEqual(compare, True)

    def test_reset(self):
        """
        test reset of existing http session
        """
        sess = trapd_http_session.init_session_obj()
        result = trapd_http_session.reset_session_obj(sess)
        compare = str(result).startswith("<requests.sessions.Session object at")
        self.assertEqual(compare, True)

    def close_existing_session(self):
        """
        test close of existing http session
        """
        sess = trapd_http_session.init_session_obj()
        result = trapd_http_session.close_session_obj(sess)
        self.assertEqual(result, True)


if __name__ == "__main__":
    unittest.main()
