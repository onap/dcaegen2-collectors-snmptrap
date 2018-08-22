import os
import pytest
import unittest
import snmptrapd
import datetime

import trapd_settings as tds
import trapd_http_session
import trapd_runtime_pid
import trapd_io
import trapd_get_cbs_config

from pysnmp.hlapi import *
from pysnmp import debug

class test_snmptrapd(unittest.TestCase):
    """
    Test the save_pid mod
    """

    pytest_json_data = "{ \"snmptrapd\": { \"version\": \"1.4.0\", \"title\": \"ONAP SNMP Trap Receiver\" }, \"protocols\": { \"transport\": \"udp\", \"ipv4_interface\": \"0.0.0.0\", \"ipv4_port\": 6162, \"ipv6_interface\": \"::1\", \"ipv6_port\": 6162 }, \"cache\": { \"dns_cache_ttl_seconds\": 60 }, \"publisher\": { \"http_timeout_milliseconds\": 1500, \"http_retries\": 3, \"http_milliseconds_between_retries\": 750, \"http_primary_publisher\": \"true\", \"http_peer_publisher\": \"unavailable\", \"max_traps_between_publishes\": 10, \"max_milliseconds_between_publishes\": 10000 }, \"streams_publishes\": { \"sec_fault_unsecure\": { \"type\": \"message_router\", \"aaf_password\": null, \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": null, \"client_role\": null, \"topic_url\": \"http://uebsb91kcdc.it.att.com:3904/events/ONAP-COLLECTOR-SNMPTRAP\" }, \"aaf_username\": null } }, \"files\": { \"runtime_base_dir\": \"/tmp/opt/app/snmptrap\", \"log_dir\": \"logs\", \"data_dir\": \"data\", \"pid_dir\": \"tmp\", \"arriving_traps_log\": \"snmptrapd_arriving_traps.log\", \"snmptrapd_diag\": \"snmptrapd_prog_diag.log\", \"traps_stats_log\": \"snmptrapd_stats.csv\", \"perm_status_file\": \"snmptrapd_status.log\", \"eelf_base_dir\": \"/tmp/opt/app/snmptrap/logs\", \"eelf_error\": \"error.log\", \"eelf_debug\": \"debug.log\", \"eelf_audit\": \"audit.log\", \"eelf_metrics\": \"metrics.log\", \"roll_frequency\": \"day\", \"minimum_severity_to_log\": 2 }, \"trap_config\": { \"sw_interval_in_seconds\": 60, \"notify_oids\": { \".1.3.6.1.4.1.9.0.1\": { \"sw_high_water_in_interval\": 102, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.2\": { \"sw_high_water_in_interval\": 101, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.3\": { \"sw_high_water_in_interval\": 102, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.4\": { \"sw_high_water_in_interval\": 10, \"sw_low_water_in_interval\": 3, \"category\": \"logonly\" } } }, \"snmpv3_config\": { \"usm_users\": [ { \"user\": \"usr-sha-aes256\", \"engineId\": \"8000000001020304\", \"usmHMACSHAAuth\": \"authkey1\", \"usmAesCfb256\": \"privkey1\" }, { \"user\": \"user1\", \"engineId\": \"8000000000000001\", \"usmHMACMD5Auth\": \"authkey1\", \"usmDESPriv\": \"privkey1\" }, { \"user\": \"user2\", \"engineId\": \"8000000000000002\", \"usmHMACSHAAuth\": \"authkey2\", \"usmAesCfb128\": \"privkey2\" }, { \"user\": \"user3\", \"engineId\": \"8000000000000003\", \"usmHMACSHAAuth\": \"authkey3\", \"usmAesCfb256\": \"privkey3\" } ] } }"

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

    def test_load_all_configs_signal(self):
        """
        Test load of all configs via runtime signal
        """

        # init vars
        tds.init()

        # request load of CBS data
        os.environ.update(CBS_SIM_JSON='/tmp/opt/app/snmptrap/etc/snmptrapd.json')
        result = trapd_get_cbs_config.get_cbs_config()
        self.assertEqual(result, True)

        # request load of CBS data
        result = snmptrapd.load_all_configs(1, 1)
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
        tds.arriving_traps_filename = tds.c_config['files']['runtime_base_dir'] + "/" + \
            tds.c_config['files']['log_dir'] + "/" + \
            (tds.c_config['files']['arriving_traps_log'])
        tds.arriving_traps_fd = trapd_io.open_file(tds.arriving_traps_filename)

        # name and open json trap log
        tds.json_traps_filename = tds.c_config['files']['runtime_base_dir'] + "/" + tds.c_config['files']['log_dir'] + "/" + "DMAAP_" + (
            tds.c_config['streams_publishes']['sec_fault_unsecure']['dmaap_info']['topic_url'].split('/')[-1]) + ".json"
        tds.json_traps_fd = trapd_io.open_file(tds.json_traps_filename)
        msg = ("published traps logged to: %s" % tds.json_traps_filename)
        trapd_io.stdout_logger(msg)
        trapd_io.ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

        # don't open files, but try to log - should raise exception
        with pytest.raises(Exception) as pytest_wrapped_exception:
            result = snmptrapd.log_all_arriving_traps()
            assert pytest_wrapped_exception.type == AttributeError

    def test_log_all_incorrect_log_type(self):
        """
        Test logging of traps
        """

        # init vars
        tds.init()

        # request load of CBS data
        os.environ.update(CBS_SIM_JSON='/tmp/opt/app/snmptrap/etc/snmptrapd.json')
        trapd_get_cbs_config.get_cbs_config()

        # open eelf logs
        trapd_io.open_eelf_logs()

    def test_v1_trap_receipt(self):
        """
        Test receiving traps
        """

        # init vars
        tds.init()

        # request load of CBS data
        os.environ.update(CBS_SIM_JSON='/tmp/opt/app/snmptrap/etc/snmptrapd.json')
        trapd_get_cbs_config.get_cbs_config()

        errorIndication, errorStatus, errorIndex, varbinds = next(sendNotification(SnmpEngine(),
             CommunityData('not_public'),
             UdpTransportTarget(('localhost', 6162)),
             ContextData(),
             'trap',
             [ObjectType(ObjectIdentity('.1.3.6.1.4.1.999.1'), OctetString('test trap - ignore')),
              ObjectType(ObjectIdentity('.1.3.6.1.4.1.999.2'), OctetString('ONAP pytest trap'))])
        )

        result = errorIndication
        self.assertEqual(result, None)

if __name__ == '__main__':
    unittest.main()
