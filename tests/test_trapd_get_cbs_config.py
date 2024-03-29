# ============LICENSE_START=======================================================
# Copyright (c) 2019-2022 AT&T Intellectual Property. All rights reserved.
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

import json
import os
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

import trapd_get_cbs_config


class test_trapd_get_cbs_config(unittest.TestCase):
    """
    Test the trapd_get_cbs_config mod
    """

    snmptrap_dir = "/tmp/opt/app/snmptrap"
    json_dir = snmptrap_dir + "/etc"

    # fmt: off
    pytest_json_data = json.loads(
        '{'
        '"snmptrapd": { '
        '    "version": "1.4.0", '
        '    "title": "ONAP SNMP Trap Receiver" }, '
        '"protocols": { '
        '    "transport": "udp", '
        '    "ipv4_interface": "0.0.0.0", '
        '    "ipv4_port": 6162, '
        '    "ipv6_interface": "::1", '
        '    "ipv6_port": 6162 }, '
        '"cache": { '
        '    "dns_cache_ttl_seconds": 60 }, '
        '"publisher": { '
        '    "http_timeout_milliseconds": 1500, '
        '    "http_retries": 3, '
        '    "http_milliseconds_between_retries": 750, '
        '    "http_primary_publisher": "true", '
        '    "http_peer_publisher": "unavailable", '
        '    "max_traps_between_publishes": 10, '
        '    "max_milliseconds_between_publishes": 10000 }, '
        '"streams_publishes": { '
        '    "sec_fault_unsecure": { '
        '        "type": "message_router", '
        '        "aaf_password": null, '
        '        "dmaap_info": { '
        '            "location": "mtl5", '
        '            "client_id": null, '
        '            "client_role": null, '
        '            "topic_url": "http://localhost:3904/events/ONAP-COLLECTOR-SNMPTRAP" }, '
        '        "aaf_username": null } }, '
        '"files": { '
        '    "runtime_base_dir": "/tmp/opt/app/snmptrap", '
        '    "log_dir": "logs", '
        '    "data_dir": "data", '
        '    "pid_dir": "tmp", '
        '    "arriving_traps_log": "snmptrapd_arriving_traps.log", '
        '    "snmptrapd_diag": "snmptrapd_prog_diag.log", '
        '    "traps_stats_log": "snmptrapd_stats.csv", '
        '    "perm_status_file": "snmptrapd_status.log", '
        '    "eelf_base_dir": "/tmp/opt/app/snmptrap/logs", '
        '    "eelf_error": "error.log", '
        '    "eelf_debug": "debug.log", '
        '    "eelf_audit": "audit.log", '
        '    "eelf_metrics": "metrics.log", '
        '    "roll_frequency": "day", '
        '    "minimum_severity_to_log": 2 }, '
        '"trap_config": { '
        '    "sw_interval_in_seconds": 60, '
        '    "notify_oids": { '
        '        ".1.3.6.1.4.1.9.0.1": { '
        '            "sw_high_water_in_interval": 102, '
        '            "sw_low_water_in_interval": 7, '
        '            "category": "logonly" }, '
        '        ".1.3.6.1.4.1.9.0.2": { '
        '            "sw_high_water_in_interval": 101, '
        '            "sw_low_water_in_interval": 7, '
        '            "category": "logonly" }, '
        '        ".1.3.6.1.4.1.9.0.3": { '
        '            "sw_high_water_in_interval": 102, '
        '            "sw_low_water_in_interval": 7, '
        '            "category": "logonly" }, '
        '        ".1.3.6.1.4.1.9.0.4": { '
        '            "sw_high_water_in_interval": 10, '
        '            "sw_low_water_in_interval": 3, '
        '            "category": "logonly" } } }, '
        '"snmpv3_config": { '
        '    "usm_users": [ { '
        '        "user": "usr-sha-aes256", '
        '        "engineId": "8000000001020304", '
        '        "usmHMACSHAAuth": "authkey1", '
        '        "usmAesCfb256": "privkey1" }, '
        '    { "user": "user1", '
        '        "engineId": "8000000000000001", '
        '        "usmHMACMD5Auth": "authkey1", '
        '        "usmDESPriv": "privkey1" }, '
        '    { "user": "user2", '
        '        "engineId": "8000000000000002", '
        '        "usmHMACSHAAuth": "authkey2", '
        '        "usmAesCfb128": "privkey2" }, '
        '    { "user": "user3", '
        '        "engineId": "8000000000000003", '
        '        "usmHMACSHAAuth": "authkey3", '
        '        "usmAesCfb256": "privkey3" } '
        '] } }'
    )
    # fmt: on


    @classmethod
    def setUpClass(cls):
        """ set up the required directory tree """
        try:
            Path(test_trapd_get_cbs_config.snmptrap_dir + "/logs").mkdir(parents=True, exist_ok=True)
            Path(test_trapd_get_cbs_config.snmptrap_dir + "/tmp").mkdir(parents=True, exist_ok=True)
            Path(test_trapd_get_cbs_config.snmptrap_dir + "/etc").mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print("Error while running %s : %s" % (os.path.basename(__file__), str(e.strerror)))
            sys.exit(1)


    def write_config(self, filename, config):
        """
        write a config file
        """
        # create snmptrapd.json for pytest
        with open(filename, "w") as outfile:
            json.dump(config, outfile)


    @patch.dict(os.environ, {"CBS_SIM_JSON": json_dir + "/snmptrapd.json"})
    def test_cbs_fallback_env_present(self):
        """
        Test that CBS fallback env variable exists and we can get config
        from fallback env var
        """
        assert os.getenv("CBS_SIM_JSON") == test_trapd_get_cbs_config.json_dir + "/snmptrapd.json"
        self.write_config(test_trapd_get_cbs_config.json_dir + "/snmptrapd.json", test_trapd_get_cbs_config.pytest_json_data)

        self.assertTrue(trapd_get_cbs_config.get_cbs_config())


    @patch.dict(os.environ, {"CBS_SIM_JSON": json_dir + "/snmptrapd.json"})
    def test_cbs_fallback_env_present_bad_numbers(self):
        """
        Test as in test_cbs_fallback_env_present(), but with
        various values reset to be non-numeric.
        """
        assert os.getenv("CBS_SIM_JSON") == test_trapd_get_cbs_config.json_dir + "/snmptrapd.json"
        with patch.dict(test_trapd_get_cbs_config.pytest_json_data):
            test_trapd_get_cbs_config.pytest_json_data["publisher"]["http_milliseconds_between_retries"] = "notanumber"
            test_trapd_get_cbs_config.pytest_json_data["files"]["minimum_severity_to_log"] = "notanumber"
            test_trapd_get_cbs_config.pytest_json_data["publisher"]["http_retries"] = "notanumber"
            self.write_config(test_trapd_get_cbs_config.json_dir + "/snmptrapd.json",
                              test_trapd_get_cbs_config.pytest_json_data)

        self.assertTrue(trapd_get_cbs_config.get_cbs_config())


    @patch.dict(os.environ, {"CBS_SIM_JSON": json_dir + "/nosuchfile.json"})
    def test_cbs_override_env_invalid(self):
        """ """
        assert os.getenv("CBS_SIM_JSON") == test_trapd_get_cbs_config.json_dir + "/nosuchfile.json"

        with self.assertRaises(SystemExit) as exc:
            result = trapd_get_cbs_config.get_cbs_config()
        self.assertEqual(str(exc.exception), "1")


    @patch.dict(os.environ, {"CONSUL_HOST": "localhost"})
    def test_cbs_env_present(self):
        """
        Test that CONSUL_HOST env variable exists but fails to
        respond
        """
        self.assertEqual(os.getenv("CONSUL_HOST"), "localhost")

        del os.environ["CBS_SIM_JSON"]
        self.assertNotIn("CBS_SIM_JSON", os.environ)

        with self.assertRaises(SystemExit) as exc:
            trapd_get_cbs_config.get_cbs_config()


    @patch.dict(os.environ, {})
    def test_cbs_override_env_undefined(self):
        """ """
        del os.environ["CBS_SIM_JSON"]
        self.assertNotIn("CBS_SIM_JSON", os.environ)

        with self.assertRaises(SystemExit) as exc:
            trapd_get_cbs_config.get_cbs_config()


if __name__ == "__main__": # pragma: no cover
    unittest.main()
