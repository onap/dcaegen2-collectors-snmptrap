import pytest
import unittest
import os

from onap_dcae_cbs_docker_client.client import get_config
from trapd_exit import cleanup_and_exit
from trapd_io import stdout_logger, ecomp_logger
import trapd_settings as tds
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
        # result = trapd_get_cbs_config.get_cbs_config()
        # print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, False)

        result = trapd_get_cbs_config.get_cbs_config()
        # fix me!
        #with pytest.raises(Exception) as pytest_wrapped_sys_exit:
            #result = trapd_get_cbs_config.get_cbs_config()
            #assert pytest_wrapped_sys_exit.type == SystemExit
            # assert pytest_wrapped_sys_exit.value.code == 1

 
    def test_cbs_override_env_invalid(self):
        """
        """
        #os.environ.update(CBS_SIM_JSON='/opt/app/snmptrap/etc/nosuchfile.json')
        # result = trapd_get_cbs_config.get_cbs_config()
        # print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, False)

        result = trapd_get_cbs_config.get_cbs_config()
        # fix me!
        #with pytest.raises(SystemExit) as pytest_wrapped_sys_exit:
            #result = trapd_get_cbs_config.get_cbs_config()
            #assert pytest_wrapped_sys_exit.type == SystemExit
            #assert pytest_wrapped_sys_exit.value.code == 1

 
    def test_cbs_fallback_env_present(self):
        """
        Test that CBS fallback env variable exists and we can get config
        from fallback env var
        """
        #os.environ.update(CBS_SIM_JSON='/opt/app/snmptrap/etc/snmptrapd.json')
        result = trapd_get_cbs_config.get_cbs_config()
        print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, True)
        self.assertEqual(result, True)
 
if __name__ == '__main__':
    unittest.main()
