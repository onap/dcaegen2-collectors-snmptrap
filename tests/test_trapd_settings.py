import pytest
import unittest
import trapd_exit

pid_file="/tmp/test_pid_file"
pid_file_dne="/tmp/test_pid_file_NOT"

import trapd_settings as tds

class test_cleanup_and_exit(unittest.TestCase):
    """
    Test for presense of required vars
    """
 

    def test_nonexistent_dict(self):
        """
        Test nosuch var
        """
        tds.init()
        try:
            tds.no_such_var
            result = True
        except:
            result = False

        self.assertEqual(result, False)
 
    def test_config_dict(self):
        """
        Test config dict
        """
        tds.init()
        try:
            tds.c_config
            result = True
        except:
            result = False

        self.assertEqual(result, True)
 
    def test_dns_cache_ip_to_name(self):
        """
        Test dns cache name dict 
        """

        tds.init()
        try:
            tds.dns_cache_ip_to_name
            result = True
        except:
            result = False

        self.assertEqual(result, True)

    def test_dns_cache_ip_expires(self):
        """
        Test dns cache ip expires dict 
        """

        tds.init()
        try:
            tds.dns_cache_ip_expires
            result = True
        except:
            result = False

        self.assertEqual(result, True)

if __name__ == '__main__':
    # tds.init()
    unittest.main()
