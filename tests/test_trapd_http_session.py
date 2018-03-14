import pytest
import unittest
import trapd_http_session
 
class test_init_session_obj(unittest.TestCase):
    """
    Test the init_session_obj mod
    """
 
    def test_correct_usage(self):
        """
        Test that attempt to create http session object works
        """
        result = trapd_http_session.init_session_obj()
        compare = str(result).startswith("<requests.sessions.Session object at")
        self.assertEqual(compare, True)
 
 
if __name__ == '__main__':
    unittest.main()
