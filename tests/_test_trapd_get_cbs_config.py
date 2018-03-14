import pytest
import unittest
import os
from onap_dcae_cbs_docker_client.client import get_config
from trapd_exit import cleanup_and_exit
from trapd_logging import stdout_logger
import trapd_get_cbs_config
 
class test_get_cbs_config(unittest.TestCase):
    """
    Test the trapd_get_cbs_config mod
    """
 
    def test_cbs_env_present(self):
        """
        Test that CBS env variable exists and we can get config even
        if CONSUL_HOST doesn't provide
        """
        os.environ.update(CONSUL_HOST='nosuchhost')
        result = trapd_get_cbs_config.trapd_get_cbs_config()
        compare = str(result).startswith("{'snmptrap': ")
        self.assertEqual(compare, False)
 
    def test_cbs_fallback_env_present(self):
        """
        Test that CBS fallback env variable exists and we can get config
        from fallback env var
        """
        os.environ.update(CBS_SIM_JSON='../etc/snmptrapd.json')
        result = trapd_get_cbs_config.trapd_get_cbs_config()
        compare = str(result).startswith("{'snmptrap': ")
        self.assertEqual(compare, False)
 
    def test_cbs_fallback_env_not_present(self):
        """
        Test that CBS fallback env variable does not exists fails
        """
        os.environ.update(CBS_SIM_JSON='../etc/no_such_file.json')
        result = trapd_get_cbs_config.trapd_get_cbs_config()
        compare = str(result).startswith("{'snmptrap': ")
        self.assertEqual(compare, False)
 
if __name__ == '__main__':
    unittest.main()
