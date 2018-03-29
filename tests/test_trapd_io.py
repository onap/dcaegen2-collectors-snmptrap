import os
import pytest
import unittest
import snmptrapd
import datetime
import json
import trapd_settings as tds
import trapd_runtime_pid
import trapd_io

class test_trapd_io(unittest.TestCase):
    """
    Test the save_pid mod
    """
    tds.c_config = json.loads("{ \"snmptrap.version\": \"1.3.0\", \"snmptrap.title\": \"ONAP SNMP Trap Receiver\" , \"protocols.transport\": \"udp\", \"protocols.ipv4_interface\": \"0.0.0.0\", \"protocols.ipv4_port\": 6164, \"protocols.ipv6_interface\": \"::1\", \"protocols.ipv6_port\": 6164, \"cache.dns_cache_ttl_seconds\": 60, \"publisher.http_timeout_milliseconds\": 1500, \"publisher.http_retries\": 3, \"publisher.http_milliseconds_between_retries\": 750, \"publisher.http_primary_publisher\": \"true\", \"publisher.http_peer_publisher\": \"unavailable\", \"publisher.max_traps_between_publishes\": 10, \"publisher.max_milliseconds_between_publishes\": 10000, \"streams_publishes\": { \"sec_measurement\": { \"type\": \"message_router\", \"aaf_password\": \"aaf_password\", \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": \"111111\", \"client_role\": \"com.att.dcae.member\", \"topic_url\": null }, \"aaf_username\": \"aaf_username\" }, \"sec_fault_unsecure\": { \"type\": \"message_router\", \"aaf_password\": null, \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": null, \"client_role\": null, \"topic_url\": \"http://uebsb93kcdc.it.att.com:3904/events/ONAP-COLLECTOR-SNMPTRAP\" }, \"aaf_username\": null } }, \"files.runtime_base_dir\": \"/tmp/opt/app/snmptrap\", \"files.log_dir\": \"logs\", \"files.data_dir\": \"data\", \"files.pid_dir\": \"/tmp/opt/app/snmptrap/tmp\", \"files.arriving_traps_log\": \"snmptrapd_arriving_traps.log\", \"files.snmptrapd_diag\": \"snmptrapd_prog_diag.log\", \"files.traps_stats_log\": \"snmptrapd_stats.csv\", \"files.perm_status_file\": \"snmptrapd_status.log\", \"files.eelf_base_dir\": \"/tmp/opt/app/snmptrap/logs\", \"files.eelf_error\": \"error.log\", \"files.eelf_debug\": \"debug.log\", \"files.eelf_audit\": \"audit.log\", \"files.eelf_metrics\": \"metrics.log\", \"files.roll_frequency\": \"hour\", \"files.minimum_severity_to_log\": 2, \"trap_def.1.trap_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.1\", \"trap_def.1.trap_category\": \"DCAE-SNMP-TRAPS\", \"trap_def.2.trap_oid\" : \"*\", \"trap_def.2.trap_category\": \"DCAE-SNMP-TRAPS\", \"stormwatch.1.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.1\", \"stormwatch.1.low_water_rearm_per_minute\" : \"5\", \"stormwatch.1.high_water_arm_per_minute\" : \"100\", \"stormwatch.2.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.2\", \"stormwatch.2.low_water_rearm_per_minute\" : \"2\", \"stormwatch.2.high_water_arm_per_minute\" : \"200\", \"stormwatch.3.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.2\", \"stormwatch.3.low_water_rearm_per_minute\" : \"2\", \"stormwatch.3.high_water_arm_per_minute\" : \"200\" }")


    def test_open_eelf_error_file(self):
        """
        Test bad error file location
        """
    
        # open eelf error logs
        tds.c_config['files.eelf_error']="/bad_dir/error.log"

        # try to open file in non-existent dir
        with pytest.raises(SystemExit) as pytest_wrapped_exception:
            result = trapd_io.open_eelf_logs()
            assert pytest_wrapped_exception.type == SystemExit

    def test_open_eelf_debug_file(self):
        """
        Test bad debug file location
        """
    
        # open eelf debug logs
        tds.c_config['files.eelf_debug']="/bad_dir/debug.log"

        # try to open file in non-existent dir
        with pytest.raises(SystemExit) as pytest_wrapped_exception:
            result = trapd_io.open_eelf_logs()
            assert pytest_wrapped_exception.type == SystemExit

    def test_open_eelf_audit_file(self):
        """
        Test bad audit file location
        """
    
        # open eelf debug logs
        tds.c_config['files.eelf_audit']="/bad_dir/audit.log"

        # try to open file in non-existent dir
        with pytest.raises(SystemExit) as pytest_wrapped_exception:
            result = trapd_io.open_eelf_logs()
            assert pytest_wrapped_exception.type == SystemExit

    def test_open_eelf_metrics_file(self):
        """
        Test bad metrics file location
        """
    
        # open eelf debug logs
        tds.c_config['files.eelf_metrics']="/bad_dir/metrics.log"

        # try to open file in non-existent dir
        with pytest.raises(SystemExit) as pytest_wrapped_exception:
            result = trapd_io.open_eelf_logs()
            assert pytest_wrapped_exception.type == SystemExit

    def test_roll_all_logs(self):
        """
        Test roll of logs when not open
        """
    
        # try to roll logs when not open
        with pytest.raises(SystemExit) as pytest_wrapped_exception:
            result = trapd_io.roll_all_logs()
            assert pytest_wrapped_exception.type == SystemExit

    def test_roll_file(self):
        """
        Test roll of individual file when not present
        """
    
        # try to roll logs when not open
        result = trapd_io.roll_file("/file/not/present")
        self.assertEqual(result, False)

    def test_open_file_exists(self):
        """
        Test file open in directory present
        """

        # create copy of snmptrapd.json for pytest
        test_file = "/tmp/snmptrap_pytest"
    
        # try to roll logs when not open
        result = trapd_io.open_file(test_file)
        compare = str(result).startswith("<_io.TextIOWrapper name=")
        self.assertEqual(compare, True)

    def test_open_file_exists_does_not_exist(self):
        """
        Test file open in directory present
        """

        # create copy of snmptrapd.json for pytest
        test_file = "/tmp/no_such_dir/snmptrap_pytest"
    
        # try to open file when dir not present
        with pytest.raises(SystemExit) as pytest_wrapped_exception:
            result = trapd_io.open_file(test_file)
            assert pytest_wrapped_exception.type == SystemExit

    def test_close_file_exists(self):
        """
        Test closing a file that's present
        """

        # create copy of snmptrapd.json for pytest
        test_file_name = "/tmp/snmptrap_pytest"
        test_file = trapd_io.open_file(test_file_name)
    
        # close active file
        result = trapd_io.close_file(test_file, test_file_name)
        self.assertEqual(result, True)

    def test_close_file_does_not_exists(self):
        """
        Test closing non-existent file 
        """

        # try to roll logs when not open
        result = trapd_io.close_file(None, None)
        self.assertEqual(result, False)


if __name__ == '__main__':
    unittest.main()
