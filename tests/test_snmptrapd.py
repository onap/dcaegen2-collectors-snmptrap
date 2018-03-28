import os
import pytest
import unittest
import snmptrapd
import datetime

import trapd_settings as tds
import trapd_http_session
import trapd_runtime_pid
import trapd_io
import trapd_logging
import trapd_get_cbs_config

class test_snmptrapd(unittest.TestCase):
    """
    Test the save_pid mod
    """

    pytest_json_data = "{ \"snmptrap.version\": \"1.3.0\", \"snmptrap.title\": \"ONAP SNMP Trap Receiver\" , \"protocols.transport\": \"udp\", \"protocols.ipv4_interface\": \"0.0.0.0\", \"protocols.ipv4_port\": 6164, \"protocols.ipv6_interface\": \"::1\", \"protocols.ipv6_port\": 6164, \"cache.dns_cache_ttl_seconds\": 60, \"publisher.http_timeout_milliseconds\": 1500, \"publisher.http_retries\": 3, \"publisher.http_milliseconds_between_retries\": 750, \"publisher.http_primary_publisher\": \"true\", \"publisher.http_peer_publisher\": \"unavailable\", \"publisher.max_traps_between_publishes\": 10, \"publisher.max_milliseconds_between_publishes\": 10000, \"streams_publishes\": { \"sec_measurement\": { \"type\": \"message_router\", \"aaf_password\": \"aaf_password\", \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": \"111111\", \"client_role\": \"com.att.dcae.member\", \"topic_url\": null }, \"aaf_username\": \"aaf_username\" }, \"sec_fault_unsecure\": { \"type\": \"message_router\", \"aaf_password\": null, \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": null, \"client_role\": null, \"topic_url\": \"http://uebsb93kcdc.it.att.com:3904/events/ONAP-COLLECTOR-SNMPTRAP\" }, \"aaf_username\": null } }, \"files.runtime_base_dir\": \"/tmp/opt/app/snmptrap\", \"files.log_dir\": \"logs\", \"files.data_dir\": \"data\", \"files.pid_dir\": \"/tmp/opt/app/snmptrap/tmp\", \"files.arriving_traps_log\": \"snmptrapd_arriving_traps.log\", \"files.snmptrapd_diag\": \"snmptrapd_prog_diag.log\", \"files.traps_stats_log\": \"snmptrapd_stats.csv\", \"files.perm_status_file\": \"snmptrapd_status.log\", \"files.eelf_base_dir\": \"/opt/app/snmptrap/logs\", \"files.eelf_error\": \"error.log\", \"files.eelf_debug\": \"debug.log\", \"files.eelf_audit\": \"audit.log\", \"files.eelf_metrics\": \"metrics.log\", \"files.roll_frequency\": \"hour\", \"files.minimum_severity_to_log\": 2, \"trap_def.1.trap_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.1\", \"trap_def.1.trap_category\": \"DCAE-SNMP-TRAPS\", \"trap_def.2.trap_oid\" : \"*\", \"trap_def.2.trap_category\": \"DCAE-SNMP-TRAPS\", \"stormwatch.1.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.1\", \"stormwatch.1.low_water_rearm_per_minute\" : \"5\", \"stormwatch.1.high_water_arm_per_minute\" : \"100\", \"stormwatch.2.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.2\", \"stormwatch.2.low_water_rearm_per_minute\" : \"2\", \"stormwatch.2.high_water_arm_per_minute\" : \"200\", \"stormwatch.3.stormwatch_oid\" : \".1.3.6.1.4.1.74.2.46.12.1.2\", \"stormwatch.3.low_water_rearm_per_minute\" : \"2\", \"stormwatch.3.high_water_arm_per_minute\" : \"200\" }"

    # create copy of snmptrapd.json for pytest
    pytest_json_config = "/tmp/opt/app/snmptrap/etc/snmptrapd.json"
    with open(pytest_json_config, 'w') as outfile:
        outfile.write(pytest_json_data)

 
    def test_usage_err(self):
        """
        Test usage error
        """

        with pytest.raises(SystemExit) as pytest_wrapped_sys_exit:
            result = snmptrapd.usage_err()
            assert pytest_wrapped_sys_exit.type == SystemExit
            assert pytest_wrapped_sys_exit.value.code == 1

 
    def test_load_all_configs(self):
        """
        Test load of all configs
        """

        # init vars
        tds.init()

        # request load of CBS data
        os.environ.update(CBS_SIM_JSON='/tmp/opt/app/snmptrap/etc/snmptrapd.json')
        result = trapd_get_cbs_config.get_cbs_config()
        self.assertEqual(result, True)

        # request load of CBS data
        result = snmptrapd.load_all_configs(0, 1)
        self.assertEqual(result, True)

    def test_log_all_arriving_traps(self):
        """
        Test logging of traps
        """

        # init vars
        tds.init()

        # request load of CBS data
        os.environ.update(CBS_SIM_JSON='/tmp/opt/app/snmptrap/etc/snmptrapd.json')
        result = trapd_get_cbs_config.get_cbs_config()

        # set last day to current
        tds.last_day = datetime.datetime.now().day

        # trap dict for logging
        tds.trap_dict = {'uuid': '06f6e91c-3236-11e8-9953-005056865aac', 'agent address': '1.2.3.4', 'agent name': 'test-agent.nodomain.com', 'cambria.partition': 'test-agent.nodomain.com', 'community': '', 'community len': 0, 'epoch_serno': 15222068260000, 'protocol version': 'v2c', 'time received': 1522206826.2938566, 'trap category': 'ONAP-COLLECTOR-SNMPTRAP', 'sysUptime': '218567736', 'notify OID': '1.3.6.1.4.1.9999.9.9.999', 'notify OID len': 10}

        # open eelf logs
        trapd_io.open_eelf_logs()

        # open trap logs
        tds.arriving_traps_filename = tds.c_config['files.runtime_base_dir'] + "/" + \
            tds.c_config['files.log_dir'] + "/" + \
            (tds.c_config['files.arriving_traps_log'])
        tds.arriving_traps_fd = trapd_io.open_file(tds.arriving_traps_filename)

        # name and open json trap log
        tds.json_traps_filename = tds.c_config['files.runtime_base_dir'] + "/" + tds.c_config['files.log_dir'] + "/" + "DMAAP_" + (
            tds.c_config['streams_publishes']['sec_fault_unsecure']['dmaap_info']['topic_url'].split('/')[-1]) + ".json"
        tds.json_traps_fd = trapd_io.open_file(tds.json_traps_filename)
        msg = ("published traps logged to: %s" % tds.json_traps_filename)
        trapd_io.stdout_logger(msg)
        trapd_logging.ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

        # don't open files, but try to log - should raise exception
        with pytest.raises(Exception) as pytest_wrapped_exception:
            result = snmptrapd.log_all_arriving_traps()
            assert pytest_wrapped_exception.type == AttributeError

if __name__ == '__main__':
    unittest.main()
