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

import unittest
import trapd_http_session
import requests
from unittest.mock import Mock, patch
import trapd_settings as tds


class test_init_session_obj(unittest.TestCase):
    """
    Test the init_session_obj mod
    """

    @classmethod
    def setUpClass(cls):
        tds.init()

    def test_init_session_obj(self):
        """
        test creation of http session
        """
        self.assertIsInstance(trapd_http_session.init_session_obj(), requests.sessions.Session)


    def test_init_session_obj_raises(self):
        """
        test close when the requests.Session() method throws an exception
        """
        with patch('requests.Session') as magic_requests:
            magic_requests.side_effect = RuntimeError("Session() throws via mock")
            with self.assertRaises(SystemExit) as exc:
                trapd_http_session.init_session_obj()
            self.assertEqual(str(exc.exception), "1")


    def test_close_nonexisting_session(self):
        """
        test close of non-existing http session
        """
        self.assertIsNone(trapd_http_session.close_session_obj(None))


    def test_close_nonexisting_close_raises(self):
        """
        test close when the session.close() method throws
        """
        class CloseThrows():
            def close(self):
                raise RuntimeError("close() throws")

        with self.assertRaises(SystemExit):
            trapd_http_session.close_session_obj(CloseThrows())


    def test_reset(self):
        """
        test reset of existing http session
        """
        sess = trapd_http_session.init_session_obj()
        self.assertIsInstance(trapd_http_session.reset_session_obj(sess), requests.sessions.Session)


    def test_close_existing_session(self):
        """
        test close of existing http session
        """
        sess = trapd_http_session.init_session_obj()
        self.assertTrue(trapd_http_session.close_session_obj(sess))


if __name__ == "__main__": # pragma: no cover
    unittest.main()
