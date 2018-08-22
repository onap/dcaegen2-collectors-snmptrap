import pytest
import unittest
import trapd_http_session
 
class test_init_session_obj(unittest.TestCase):
    """
    Test the init_session_obj mod
    """
 
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
 
    def close_nonexistent_session(self):
        """
        test close of non-existent http session
        """
        result = trapd_http_session.close_session_obj(None)
        self.assertEqual(result, True)
 
if __name__ == '__main__':
    unittest.main()
