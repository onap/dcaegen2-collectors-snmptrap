import pytest
import unittest
import os
import sys

from onap_dcae_cbs_docker_client.client import get_config
from trapd_exit import cleanup_and_exit
from trapd_io import stdout_logger, ecomp_logger
import trapd_settings as tds
import trapd_get_cbs_config

from pathlib import Path

# # # # # # # #
# ENV setup
# # # # # # # #

# required directory tree
try:
    Path("/tmp/opt/app/snmptrap/logs").mkdir(parents=True, exist_ok=True)
    Path("/tmp/opt/app/snmptrap/tmp").mkdir(parents=True, exist_ok=True)
except Exception as e:
    print("Error while running %s : %s" % (os.path.basename(__file__), str(e.strerror)))
    sys.exit(1)

# env var for CBS_SIM_JSON
try:
    os.environ['CBS_SIM_JSON'] = "/tmp/opt/app/snmptrap/etc/snmptrapd.json"
except Exception as e:
    print("Error while running %s : %s" % (os.path.basename(__file__), str(e.strerror)))
    sys.exit(1)

pytest_json_data = "{ \"snmptrapd\": { \"version\": \"1.4.0\", \"title\": \"ONAP SNMP Trap Receiver\" }, \"protocols\": { \"transport\": \"udp\", \"ipv4_interface\": \"0.0.0.0\", \"ipv4_port\": 6162, \"ipv6_interface\": \"::1\", \"ipv6_port\": 6162 }, \"cache\": { \"dns_cache_ttl_seconds\": 60 }, \"publisher\": { \"http_timeout_milliseconds\": 1500, \"http_retries\": 3, \"http_milliseconds_between_retries\": 750, \"http_primary_publisher\": \"true\", \"http_peer_publisher\": \"unavailable\", \"max_traps_between_publishes\": 10, \"max_milliseconds_between_publishes\": 10000 }, \"streams_publishes\": { \"sec_fault_unsecure\": { \"type\": \"message_router\", \"aaf_password\": null, \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": null, \"client_role\": null, \"topic_url\": \"http://localhost:3904/events/ONAP-COLLECTOR-SNMPTRAP\" }, \"aaf_username\": null } }, \"files\": { \"runtime_base_dir\": \"/tmp/opt/app/snmptrap\", \"log_dir\": \"logs\", \"data_dir\": \"data\", \"pid_dir\": \"tmp\", \"arriving_traps_log\": \"snmptrapd_arriving_traps.log\", \"snmptrapd_diag\": \"snmptrapd_prog_diag.log\", \"traps_stats_log\": \"snmptrapd_stats.csv\", \"perm_status_file\": \"snmptrapd_status.log\", \"eelf_base_dir\": \"/tmp/opt/app/snmptrap/logs\", \"eelf_error\": \"error.log\", \"eelf_debug\": \"debug.log\", \"eelf_audit\": \"audit.log\", \"eelf_metrics\": \"metrics.log\", \"roll_frequency\": \"day\", \"minimum_severity_to_log\": 2 }, \"trap_config\": { \"sw_interval_in_seconds\": 60, \"notify_oids\": { \".1.3.6.1.4.1.9.0.1\": { \"sw_high_water_in_interval\": 102, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.2\": { \"sw_high_water_in_interval\": 101, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.3\": { \"sw_high_water_in_interval\": 102, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.4\": { \"sw_high_water_in_interval\": 10, \"sw_low_water_in_interval\": 3, \"category\": \"logonly\" } } }, \"snmpv3_config\": { \"usm_users\": [ { \"user\": \"usr-sha-aes256\", \"engineId\": \"8000000001020304\", \"usmHMACSHAAuth\": \"authkey1\", \"usmAesCfb256\": \"privkey1\" }, { \"user\": \"user1\", \"engineId\": \"8000000000000001\", \"usmHMACMD5Auth\": \"authkey1\", \"usmDESPriv\": \"privkey1\" }, { \"user\": \"user2\", \"engineId\": \"8000000000000002\", \"usmHMACSHAAuth\": \"authkey2\", \"usmAesCfb128\": \"privkey2\" }, { \"user\": \"user3\", \"engineId\": \"8000000000000003\", \"usmHMACSHAAuth\": \"authkey3\", \"usmAesCfb256\": \"privkey3\" } ] } }"

# create snmptrapd.json for pytest
pytest_json_config = os.getenv('CBS_SIM_JSON')
with open(pytest_json_config, 'w') as outfile:
    outfile.write(pytest_json_data)
outfile.close()

# test class/methods
class test_get_cbs_config(unittest.TestCase):
    """
    Test the trapd_get_cbs_config mod
    """

    def test_cbs_fallback_env_present(self):
        """
        Test that CBS fallback env variable exists and we can get config
        from fallback env var
        """
        os.environ.update(CBS_SIM_JSON='/tmp/opt/app/snmptrap/etc/snmptrapd.json')
        result = trapd_get_cbs_config.get_cbs_config()
        print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, True)
        self.assertEqual(result, True)

    def test_cbs_override_env_invalid(self):
        """
        """
        os.environ.update(CBS_SIM_JSON='/tmp/opt/app/snmptrap/etc/nosuchfile.json')
        # result = trapd_get_cbs_config.get_cbs_config()
        # print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, False)

        with pytest.raises(SystemExit) as pytest_wrapped_sys_exit:
            result = trapd_get_cbs_config.get_cbs_config()
            assert pytest_wrapped_sys_exit.type == SystemExit
            # assert pytest_wrapped_sys_exit.value.code == 1
 
    def test_cbs_env_present(self):
        """
        Test that CONSUL_HOST env variable exists but fails to
        respond
        """
        os.environ.update(CONSUL_HOST='localhost')
        del os.environ['CBS_SIM_JSON']
        # result = trapd_get_cbs_config.get_cbs_config()
        # print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, False)

        with pytest.raises(SystemExit) as sys_exit:
            trapd_get_cbs_config.get_cbs_config()
            assert sys_exit.value.errno == errno.ECONNREFUSED 
 
    def test_cbs_override_env_undefined(self):
        """
        """
        print("------>>>  RUNNING test_no_cbs_override_env_var:")
        del os.environ['CBS_SIM_JSON']
    
        with pytest.raises(SystemExit) as pytest_wrapped_sys_exit:
            assert trapd_get_cbs_config.get_cbs_config() == SystemExit
 
if __name__ == '__main__':
    unittest.main()
