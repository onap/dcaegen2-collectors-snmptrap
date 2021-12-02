# ============LICENSE_START=======================================================
# Copyright (c) 2019-2021 AT&T Intellectual Property. All rights reserved.
# ================================================================================
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ============LICENSE_END=========================================================

import pytest
import json
import unittest
import os

from onap_dcae_cbs_docker_client.client import get_config
from trapd_exit import cleanup_and_exit
from trapd_io import stdout_logger, ecomp_logger
import trapd_settings as tds
import trapd_snmpv3

from pysnmp.entity import engine, config


class test_snmpv3_config(unittest.TestCase):
    """
    Test snmpv3 module
    """

    def test_v3_config_present(self):
        """
        Test that snmpv3 config is present
        """
        tds.c_config = json.loads(
            '{ "snmptrapd": { "version": "1.4.0", "title": "ONAP SNMP Trap Receiver" }, "protocols": { "transport": "udp", "ipv4_interface": "0.0.0.0", "ipv4_port": 6162, "ipv6_interface": "::1", "ipv6_port": 6162 }, "cache": { "dns_cache_ttl_seconds": 60 }, "publisher": { "http_timeout_milliseconds": 1500, "http_retries": 3, "http_milliseconds_between_retries": 750, "http_primary_publisher": "true", "http_peer_publisher": "unavailable", "max_traps_between_publishes": 10, "max_milliseconds_between_publishes": 10000 }, "streams_publishes": { "sec_fault_unsecure": { "type": "message_router", "aaf_password": null, "dmaap_info": { "location": "mtl5", "client_id": null, "client_role": null, "topic_url": "http://localhost:3904/events/ONAP-COLLECTOR-SNMPTRAP" }, "aaf_username": null } }, "files": { "runtime_base_dir": "/tmp/opt/app/snmptrap", "log_dir": "logs", "data_dir": "data", "pid_dir": "tmp", "arriving_traps_log": "snmptrapd_arriving_traps.log", "snmptrapd_diag": "snmptrapd_prog_diag.log", "traps_stats_log": "snmptrapd_stats.csv", "perm_status_file": "snmptrapd_status.log", "eelf_base_dir": "/tmp/opt/app/snmptrap/logs", "eelf_error": "error.log", "eelf_debug": "debug.log", "eelf_audit": "audit.log", "eelf_metrics": "metrics.log", "roll_frequency": "day", "minimum_severity_to_log": 2 }, "trap_config": { "sw_interval_in_seconds": 60, "notify_oids": { ".1.3.6.1.4.1.9.0.1": { "sw_high_water_in_interval": 102, "sw_low_water_in_interval": 7, "category": "logonly" }, ".1.3.6.1.4.1.9.0.2": { "sw_high_water_in_interval": 101, "sw_low_water_in_interval": 7, "category": "logonly" }, ".1.3.6.1.4.1.9.0.3": { "sw_high_water_in_interval": 102, "sw_low_water_in_interval": 7, "category": "logonly" }, ".1.3.6.1.4.1.9.0.4": { "sw_high_water_in_interval": 10, "sw_low_water_in_interval": 3, "category": "logonly" } } }, "snmpv3_config": { "usm_users": [ { "user": "usr-sha-aes256", "engineId": "8000000001020304", "usmHMACSHAAuth": "authkey1", "usmAesCfb256": "privkey1" }, { "user": "user1", "engineId": "8000000000000001", "usmHMACMD5Auth": "authkey1", "usmDESPriv": "privkey1" }, { "user": "user2", "engineId": "8000000000000002", "usmHMACSHAAuth": "authkey2", "usmAesCfb128": "privkey2" }, { "user": "user3", "engineId": "8000000000000003", "usmHMACSHAAuth": "authkey3", "usmAesCfb256": "privkey3" }, { "user": "user4"} , { "engineId": "1"}, { "user": "user6", "engineId": "8000000000000006", "usmNoAuth": "authkey3", "usmAesCfb192": "privkey6" }, { "user": "user7", "engineId": "8000000000000007", "usmNoAuth": "", "usmNoPriv": "" }] } }'
        )

        # del os.environ['CBS_SIM_JSON']
        # result = trapd_get_cbs_config.get_cbs_config()
        # print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, False)

        with pytest.raises(Exception) as pytest_wrapped_sys_exit:
            snmp_engine = engine.SnmpEngine()
            result = trapd_snmpv3.load_snmpv3_credentials(config, snmp_engine, tds.c_config)
            # config, snmp_engine=trapd_snmpv3.load_snmpv3_credentials(config, snmp_engine, pytest_json_data_with_v3)
            assert pytest_wrapped_sys_exit.type == SystemExit
            # assert pytest_wrapped_sys_exit.value.code == 1

    def test_v3_config_not_present(self):
        """
        Test that app is ok if v3 config not present
        """
        tds.c_config = json.loads(
            '{ "snmptrapd": { "version": "1.4.0", "title": "ONAP SNMP Trap Receiver" }, "protocols": { "transport": "udp", "ipv4_interface": "0.0.0.0", "ipv4_port": 6162, "ipv6_interface": "::1", "ipv6_port": 6162 }, "cache": { "dns_cache_ttl_seconds": 60 }, "publisher": { "http_timeout_milliseconds": 1500, "http_retries": 3, "http_milliseconds_between_retries": 750, "http_primary_publisher": "true", "http_peer_publisher": "unavailable", "max_traps_between_publishes": 10, "max_milliseconds_between_publishes": 10000 }, "streams_publishes": { "sec_fault_unsecure": { "type": "message_router", "aaf_password": null, "dmaap_info": { "location": "mtl5", "client_id": null, "client_role": null, "topic_url": "http://localhost:3904/events/ONAP-COLLECTOR-SNMPTRAP" }, "aaf_username": null } }, "files": { "runtime_base_dir": "/tmp/opt/app/snmptrap", "log_dir": "logs", "data_dir": "data", "pid_dir": "tmp", "arriving_traps_log": "snmptrapd_arriving_traps.log", "snmptrapd_diag": "snmptrapd_prog_diag.log", "traps_stats_log": "snmptrapd_stats.csv", "perm_status_file": "snmptrapd_status.log", "eelf_base_dir": "/tmp/opt/app/snmptrap/logs", "eelf_error": "error.log", "eelf_debug": "debug.log", "eelf_audit": "audit.log", "eelf_metrics": "metrics.log", "roll_frequency": "day", "minimum_severity_to_log": 2 }, "trap_config": { "sw_interval_in_seconds": 60, "notify_oids": { ".1.3.6.1.4.1.9.0.1": { "sw_high_water_in_interval": 102, "sw_low_water_in_interval": 7, "category": "logonly" }, ".1.3.6.1.4.1.9.0.2": { "sw_high_water_in_interval": 101, "sw_low_water_in_interval": 7, "category": "logonly" }, ".1.3.6.1.4.1.9.0.3": { "sw_high_water_in_interval": 102, "sw_low_water_in_interval": 7, "category": "logonly" }, ".1.3.6.1.4.1.9.0.4": { "sw_high_water_in_interval": 10, "sw_low_water_in_interval": 3, "category": "logonly" } } } }'
        )

        # del os.environ['CBS_SIM_JSON']
        # result = trapd_get_cbs_config.get_cbs_config()
        # print("result: %s" % result)
        # compare = str(result).startswith("{'snmptrap': ")
        # self.assertEqual(compare, False)

        with pytest.raises(Exception) as pytest_wrapped_sys_exit:
            snmp_engine = engine.SnmpEngine()
            result = trapd_snmpv3.load_snmpv3_credentials(config, snmp_engine, tds.c_config)
            # config, snmp_engine=trapd_snmpv3.load_snmpv3_credentials(config, snmp_engine, pytest_json_data_with_v3)
            assert pytest_wrapped_sys_exit.type == SystemExit
            # assert pytest_wrapped_sys_exit.value.code == 1


if __name__ == "__main__":
    unittest.main()
