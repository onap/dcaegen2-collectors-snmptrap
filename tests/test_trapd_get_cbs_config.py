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

    pytest_json_data = "{ \"snmptrap.version\": \"1.3.0\", \"snmptrap.title\": \"ONAP SNMP Trap Receiver\" , \"protocols.transport\": \"udp\", \"protocols.ipv4_interface\": \"0.0.0.0\", \"protocols.ipv4_port\": 6164, \"protocols.ipv6_interface\": \"::1\", \"protocols.ipv6_port\": 6164, \"cache.dns_cache_ttl_seconds\": 60, \"publisher.http_timeout_milliseconds\": 1500, \"publisher.http_retries\": 3, \"publisher.http_milliseconds_between_retries\": 750, \"publisher.http_primary_publisher\": \"true\", \"publisher.http_peer_publisher\": \"unavailable\", \"publisher.max_traps_between_publishes\": 10, \"publisher.max_milliseconds_between_publishes\": 10000, \"streams_publishes\": { \"sec_measurement\": { \"type\": \"message_router\", \"aaf_password\": \"aaf_password\", \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": \"111111\", \"client_role\": \"com.att.dcae.member\", \"topic_url\": null }, \"aaf_username\": \"aaf_username\" }, \"sec_fault_unsecure\": { \"type\": \"message_router\", \"aaf_password\": null, \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": null, \"client_role\": null, \"topic_url\": \"http://uebsb93kcdc.it.att.com:3904/events/ONAP-COLLECTOR-SNMPTRAP\" }, \"aaf_username\": null } }, \"files.runtime_base_dir\": \"/tmp/opt/app/snmptrap\", \"files.log_dir\": \"logs\", \"files.data_dir\": \"data\", \"files.pid_dir\": \"/tmp/opt/app/snmptrap/tmp\", \"files.arriving_traps_log\": \"snmptrapd_arriving_traps.log\", \"files.snmptrapd_diag\": \"snmptrapd_prog_diag.log\", \"files.traps_stats_log\": \"snmptrapd_stats.csv\", \"files.perm_status_file\": \"snmptrapd_status.log\", \"files.eelf_base_dir\": \"/opt/app/snmptrap/logs\", \"files.eelf_error\": \"error.log\", \"files.eelf_debug\": \"debug.log\", \"files.eelf_audit\": \"audit.log\", \"files.eelf_metrics\": \"metrics.log\", \"files.roll_frequency\": \"hour\", \"files.minimum_severity_to_log\": 2, \"trap_def.1.trap_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.1\", \"trap_def.1.trap_category\": \"DCAE-SNMP-TRAPS\", \"trap_def.2.trap_oid\" : \"*\", \"trap_def.2.trap_category\": \"DCAE-SNMP-TRAPS\", \"stormwatch.1.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.1\", \"stormwatch.1.low_water_rearm_per_minute\" : \"5\", \"stormwatch.1.high_water_arm_per_minute\" : \"100\", \"stormwatch.2.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.2\", \"stormwatch.2.low_water_rearm_per_minute\" : \"2\", \"stormwatch.2.high_water_arm_per_minute\" : \"200\", \"stormwatch.3.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.2\", \"stormwatch.3.low_water_rearm_per_minute\" : \"2\", \"stormwatch.3.high_water_arm_per_minute\" : \"200\" }"

    # create copy of snmptrapd.json for pytest
    pytest_json_config = "/tmp/opt/app/snmptrap/etc/snmptrapd.json"
    with open(pytest_json_config, 'w') as outfile:
        outfile.write(pytest_json_data)

 
    def test_cbs_env_present(self):
        """
        Test that CONSUL_HOST env variable exists but fails to
        respond
        """
        os.environ.update(CONSUL_HOST='nosuchhost')
        # del os.environ['CBS_SIM_JSON']
        # result = trapd_get_cbs_config.get_cbs_config()
        # print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, False)

        with pytest.raises(Exception) as pytest_wrapped_sys_exit:
            result = trapd_get_cbs_config.get_cbs_config()
            assert pytest_wrapped_sys_exit.type == SystemExit
            # assert pytest_wrapped_sys_exit.value.code == 1

 
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
            assert pytest_wrapped_sys_exit.value.code == 1

 
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
 
if __name__ == '__main__':
    unittest.main()
