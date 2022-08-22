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
import unittest
import os
import traceback

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

    JSON_START = (
        '{'
        '    "snmptrapd": {'
        '        "version": "2.0",'
        '        "title": "ONAP SNMP Trap Receiver"'
        '    },'
        '    "protocols": {'
        '        "transport": "udp",'
        '        "ipv4_interface": "0.0.0.0",'
        '        "ipv4_port": 6162,'
        '        "ipv6_interface": "::1",'
        '        "ipv6_port": 6162'
        '    },'
        '    "cache": {'
        '        "dns_cache_ttl_seconds": 10800'
        '    },'
        '    "publisher": {'
        '        "http_milliseconds_timeout": 500,'
        '        "http_retries": 2,'
        '        "http_milliseconds_between_retries": 250,'
        '        "http_primary_publisher": "true",'
        '        "http_peer_publisher": "unavailable",'
        '        "max_traps_between_publishes": 10,'
        '        "max_milliseconds_between_publishes": 10000'
        '    },'
        '    "streams_publishes": {'
        '        "sec_fault_unsecure": {'
        '            "type": "message_router",'
        '            "aaf_password": null,'
        '            "dmaap_info": {'
        '                "location": "mtl5",'
        '                "client_id": null,'
        '                "client_role": null,'
        '                "topic_url": "http://localhost:3904/events/unauthenticated.ONAP-COLLECTOR-SNMPTRAP"'
        '            },'
        '            "aaf_username": null'
        '        }'
        '    },'
        '    "files": {'
        '        "runtime_base_dir": "/tmp/opt/app/snmptrap",'
        '        "log_dir": "logs",'
        '        "data_dir": "data",'
        '        "pid_dir": "tmp",'
        '        "arriving_traps_log": "snmptrapd_arriving_traps.log",'
        '        "snmptrapd_diag": "snmptrapd_prog_diag.log",'
        '        "traps_stats_log": "snmptrapd_stats.csv",'
        '        "perm_status_file": "snmptrapd_status.log",'
        '        "eelf_base_dir": "/tmp/opt/app/snmptrap/logs",'
        '        "eelf_error": "error.log",'
        '        "eelf_debug": "debug.log",'
        '        "eelf_audit": "audit.log",'
        '        "eelf_metrics": "metrics.log",'
        '        "roll_frequency": "hour",'
        '        "minimum_severity_to_log": 3'
        '    },'
        '    "check_hb_traps": {'
        '        "trap_thr": 900,'
        '        "hb_thr": 900,'
        '        "hb_notify_oid": ".1.3.6.1.4.1.74.2.46.12.1.1"'
        '    },'
        '    "trap_config": {'
        '        "sw_interval_in_seconds": 60,'
        '        "metric_log_notification_threshold_pct": 25,'
        '        "notify_oids": ['
        '            {'
        '                "oid": ".1.3.6.1.4.1.9.0.1",'
        '                "sw_high_water_in_interval": 100,'
        '                "sw_low_water_in_interval": 5,'
        '                "category": "logonly"'
        '            },'
        '            {'
        '                "oid": ".1.3.6.1.4.1.9.0.2",'
        '                "sw_high_water_in_interval": 200,'
        '                "sw_low_water_in_interval": 10,'
        '                "category": "logonly"'
        '            },'
        '            {'
        '                "oid": ".1.3.6.1.4.1.9.0.3",'
        '                "sw_high_water_in_interval": 300,'
        '                "sw_low_water_in_interval": 15,'
        '                "category": "logonly"'
        '            }'
        '        ]'
        '    }'
    )
    JSON_USERS = (
        '    "snmpv3_config": {'
        '        "usm_users": ['
        '            {'
        '                "user": "user1",'
        '                "engineId": "8000000000000001",'
        '                "usmHMACMD5AuthProtocol": "authkey1",'
        '                "usmDESPrivProtocol": "privkey1"'
        '            },'
        '            {'
        '                "user": "user2",'
        '                "engineId": "8000000000000002",'
        '                "usmHMACMD5AuthProtocol": "authkey2",'
        '                "usm3DESEDEPrivProtocol": "privkey2"'
        '            },'
        '            {'
        '                "user": "user3",'
        '                "engineId": "8000000000000003",'
        '                "usmHMACMD5AuthProtocol": "authkey3",'
        '                "usmAesCfb128Protocol": "privkey3"'
        '            },'
        '            {'
        '                "user": "user4",'
        '                "engineId": "8000000000000004",'
        '                "usmHMACMD5AuthProtocol": "authkey4",'
        '                "usmAesBlumenthalCfb192Protocol": "privkey4"'
        '            },'
        '            {'
        '                "user": "user5",'
        '                "engineId": "8000000000000005",'
        '                "usmHMACMD5AuthProtocol": "authkey5",'
        '                "usmAesBlumenthalCfb256Protocol": "privkey5"'
        '            },'
        '            {'
        '                "user": "user6",'
        '                "engineId": "8000000000000006",'
        '                "usmHMACMD5AuthProtocol": "authkey6",'
        '                "usmAesCfb192Protocol": "privkey6"'
        '            },'
        '            {'
        '                "user": "user7",'
        '                "engineId": "8000000000000007",'
        '                "usmHMACMD5AuthProtocol": "authkey7",'
        '                "usmAesCfb256Protocol": "privkey7"'
        '            },'
        '            {'
        '                "user": "user9",'
        '                "engineId": "8000000000000009",'
        '                "usmHMACSHAAuthProtocol": "authkey9",'
        '                "usmDESPrivProtocol": "privkey9"'
        '            },'
        '            {'
        '                "user": "user10",'
        '                "engineId": "8000000000000010",'
        '                "usmHMACSHAAuthProtocol": "authkey10",'
        '                "usm3DESEDEPrivProtocol": "privkey10"'
        '            },'
        '            {'
        '                "user": "user11",'
        '                "engineId": "8000000000000011",'
        '                "usmHMACSHAAuthProtocol": "authkey11",'
        '                "usmAesCfb128Protocol": "privkey11"'
        '            },'
        '            {'
        '                "user": "user12",'
        '                "engineId": "8000000000000012",'
        '                "usmHMACSHAAuthProtocol": "authkey12",'
        '                "usmAesBlumenthalCfb192Protocol": "privkey12"'
        '            },'
        '            {'
        '                "user": "user13",'
        '                "engineId": "8000000000000013",'
        '                "usmHMACSHAAuthProtocol": "authkey13",'
        '                "usmAesBlumenthalCfb256Protocol": "privkey13"'
        '            },'
        '            {'
        '                "user": "user14",'
        '                "engineId": "8000000000000014",'
        '                "usmHMACSHAAuthProtocol": "authkey14",'
        '                "usmAesCfb192Protocol": "privkey14"'
        '            },'
        '            {'
        '                "user": "user15",'
        '                "engineId": "8000000000000015",'
        '                "usmHMACSHAAuthProtocol": "authkey15",'
        '                "usmAesCfb256Protocol": "privkey15"'
        '            },'
        '            {'
        '                "user": "user17",'
        '                "engineId": "8000000000000017",'
        '                "usmHMAC128SHA224AuthProtocol": "authkey17",'
        '                "usmDESPrivProtocol": "privkey17"'
        '            },'
        '            {'
        '                "user": "user18",'
        '                "engineId": "8000000000000018",'
        '                "usmHMAC128SHA224AuthProtocol": "authkey18",'
        '                "usm3DESEDEPrivProtocol": "privkey18"'
        '            },'
        '            {'
        '                "user": "user19",'
        '                "engineId": "8000000000000019",'
        '                "usmHMAC128SHA224AuthProtocol": "authkey19",'
        '                "usmAesCfb128Protocol": "privkey19"'
        '            },'
        '            {'
        '                "user": "user20",'
        '                "engineId": "8000000000000020",'
        '                "usmHMAC128SHA224AuthProtocol": "authkey20",'
        '                "usmAesBlumenthalCfb192Protocol": "privkey20"'
        '            },'
        '            {'
        '                "user": "user21",'
        '                "engineId": "8000000000000021",'
        '                "usmHMAC128SHA224AuthProtocol": "authkey21",'
        '                "usmAesBlumenthalCfb256Protocol": "privkey21"'
        '            },'
        '            {'
        '                "user": "user22",'
        '                "engineId": "8000000000000022",'
        '                "usmHMAC128SHA224AuthProtocol": "authkey22",'
        '                "usmAesCfb192Protocol": "privkey22"'
        '            },'
        '            {'
        '                "user": "user23",'
        '                "engineId": "8000000000000023",'
        '                "usmHMAC128SHA224AuthProtocol": "authkey23",'
        '                "usmAesCfb256Protocol": "privkey23"'
        '            },'
        '            {'
        '                "user": "user25",'
        '                "engineId": "8000000000000025",'
        '                "usmHMAC192SHA256AuthProtocol": "authkey25",'
        '                "usmDESPrivProtocol": "privkey25"'
        '            },'
        '            {'
        '                "user": "user26",'
        '                "engineId": "8000000000000026",'
        '                "usmHMAC192SHA256AuthProtocol": "authkey26",'
        '                "usm3DESEDEPrivProtocol": "privkey26"'
        '            },'
        '            {'
        '                "user": "user27",'
        '                "engineId": "8000000000000027",'
        '                "usmHMAC192SHA256AuthProtocol": "authkey27",'
        '                "usmAesCfb128Protocol": "privkey27"'
        '            },'
        '            {'
        '                "user": "user28",'
        '                "engineId": "8000000000000028",'
        '                "usmHMAC192SHA256AuthProtocol": "authkey28",'
        '                "usmAesBlumenthalCfb192Protocol": "privkey28"'
        '            },'
        '            {'
        '                "user": "user29",'
        '                "engineId": "8000000000000029",'
        '                "usmHMAC192SHA256AuthProtocol": "authkey29",'
        '                "usmAesBlumenthalCfb256Protocol": "privkey29"'
        '            },'
        '            {'
        '                "user": "user30",'
        '                "engineId": "8000000000000030",'
        '                "usmHMAC192SHA256AuthProtocol": "authkey30",'
        '                "usmAesCfb192Protocol": "privkey30"'
        '            },'
        '            {'
        '                "user": "user31",'
        '                "engineId": "8000000000000031",'
        '                "usmHMAC192SHA256AuthProtocol": "authkey31",'
        '                "usmAesCfb256Protocol": "privkey31"'
        '            },'
        '            {'
        '                "user": "user33",'
        '                "engineId": "8000000000000033",'
        '                "usmHMAC256SHA384AuthProtocol": "authkey33",'
        '                "usmDESPrivProtocol": "privkey33"'
        '            },'
        '            {'
        '                "user": "user34",'
        '                "engineId": "8000000000000034",'
        '                "usmHMAC256SHA384AuthProtocol": "authkey34",'
        '                "usm3DESEDEPrivProtocol": "privkey34"'
        '            },'
        '            {'
        '                "user": "user35",'
        '                "engineId": "8000000000000035",'
        '                "usmHMAC256SHA384AuthProtocol": "authkey35",'
        '                "usmAesCfb128Protocol": "privkey35"'
        '            },'
        '            {'
        '                "user": "user36",'
        '                "engineId": "8000000000000036",'
        '                "usmHMAC256SHA384AuthProtocol": "authkey36",'
        '                "usmAesBlumenthalCfb192Protocol": "privkey36"'
        '            },'
        '            {'
        '                "user": "user37",'
        '                "engineId": "8000000000000037",'
        '                "usmHMAC256SHA384AuthProtocol": "authkey37",'
        '                "usmAesBlumenthalCfb256Protocol": "privkey37"'
        '            },'
        '            {'
        '                "user": "user38",'
        '                "engineId": "8000000000000038",'
        '                "usmHMAC256SHA384AuthProtocol": "authkey38",'
        '                "usmAesCfb192Protocol": "privkey38"'
        '            },'
        '            {'
        '                "user": "user39",'
        '                "engineId": "8000000000000039",'
        '                "usmHMAC256SHA384AuthProtocol": "authkey39",'
        '                "usmAesCfb256Protocol": "privkey39"'
        '            },'
        '            {'
        '                "user": "user41",'
        '                "engineId": "8000000000000041",'
        '                "usmHMAC384SHA512AuthProtocol": "authkey41",'
        '                "usmDESPrivProtocol": "privkey41"'
        '            },'
        '            {'
        '                "user": "user42",'
        '                "engineId": "8000000000000042",'
        '                "usmHMAC384SHA512AuthProtocol": "authkey42",'
        '                "usm3DESEDEPrivProtocol": "privkey42"'
        '            },'
        '            {'
        '                "user": "user43",'
        '                "engineId": "8000000000000043",'
        '                "usmHMAC384SHA512AuthProtocol": "authkey43",'
        '                "usmAesCfb128Protocol": "privkey43"'
        '            },'
        '            {'
        '                "user": "user44",'
        '                "engineId": "8000000000000044",'
        '                "usmHMAC384SHA512AuthProtocol": "authkey44",'
        '                "usmAesBlumenthalCfb192Protocol": "privkey44"'
        '            },'
        '            {'
        '                "user": "user45",'
        '                "engineId": "8000000000000045",'
        '                "usmHMAC384SHA512AuthProtocol": "authkey45",'
        '                "usmAesBlumenthalCfb256Protocol": "privkey45"'
        '            },'
        '            {'
        '                "user": "user46",'
        '                "engineId": "8000000000000046",'
        '                "usmHMAC384SHA512AuthProtocol": "authkey46",'
        '                "usmAesCfb192Protocol": "privkey46"'
        '            },'
        '            {'
        '                "user": "user47",'
        '                "engineId": "8000000000000047",'
        '                "usmHMAC384SHA512AuthProtocol": "authkey47",'
        '                "usmAesCfb256Protocol": "privkey47"'
        '            },'
        '            {'
        '                "user": "user48",'
        '                "engineId": "8000000000000048",'
        '                "usmNoAuthProtocol": "authkey48",'
        '                "usmNoPrivProtocol": "privkey48"'
        '            },'
        '            {'
        '                "user": "user49",'
        '                "engineId": "8000000000000049",'
        '                "unknownAuthProtocol": "authkey49",'
        '                "unknownProtocol": "privkey49"'
        '            }'
        '        ]'
        '    }'
    )
    JSON_MISSING_USER = (
        '    "snmpv3_config": {'
        '        "usm_users": ['
        '            {'
        '                "baduser": "user50",'
        '                "engineId": "8000000000000050",'
        '                "unknownAuthProtocol": "authkey50",'
        '                "unknownProtocol": "privkey50"'
        '            }'
        '        ]'
        '    }'
    )
    JSON_MISSING_ENGINE = (
        '    "snmpv3_config": {'
        '        "usm_users": ['
        '            {'
        '                "user": "user51",'
        '                "badengineId": "8000000000000051",'
        '                "unknownAuthProtocol": "authkey51",'
        '                "unknownProtocol": "privkey51"'
        '            }'
        '        ]'
        '    }'
    )
    JSON_COMMA = ','
    JSON_END = '}'

    @classmethod
    def setUpClass(cls):
        tds.init()


    def test_v3_config_present(self):
        """
        Test that snmpv3 config is present
        """
        pconfig = (
            test_snmpv3_config.JSON_START +
            test_snmpv3_config.JSON_COMMA +
            test_snmpv3_config.JSON_USERS +
            test_snmpv3_config.JSON_END
        )
        tds.c_config = json.loads(pconfig)

        snmp_engine = engine.SnmpEngine()
        rconfig, rsnmp_engine = trapd_snmpv3.load_snmpv3_credentials(config, snmp_engine, tds.c_config)
        self.assertEqual(rsnmp_engine, snmp_engine)


    def test_v3_config_not_present(self):
        """
        Test that app is ok if v3 config not present
        """
        pconfig = (
            test_snmpv3_config.JSON_START +
            test_snmpv3_config.JSON_END
            )
        tds.c_config = json.loads(pconfig)

        snmp_engine = engine.SnmpEngine()
        rconfig, rsnmp_engine = trapd_snmpv3.load_snmpv3_credentials(config, snmp_engine, tds.c_config)
        self.assertEqual(rsnmp_engine, snmp_engine)


    @unittest.skip("need to understand what happens when a username is missing")
    def test_v3_config_missing_user(self):
        """
        Test that app is ok if v3 config has a missing user name
        """
        pconfig = (
            test_snmpv3_config.JSON_START +
            test_snmpv3_config.JSON_COMMA +
            test_snmpv3_config.JSON_MISSING_USER +
            test_snmpv3_config.JSON_END
            )
        tds.c_config = json.loads(pconfig)

        snmp_engine = engine.SnmpEngine()
        rconfig, rsnmp_engine = trapd_snmpv3.load_snmpv3_credentials(config, snmp_engine, tds.c_config)
        self.assertEqual(rsnmp_engine, snmp_engine)


    def test_v3_config_missing_engine(self):
        """
        Test that app is ok if v3 config has a missing engine name
        """
        pconfig = (
            test_snmpv3_config.JSON_START +
            test_snmpv3_config.JSON_COMMA +
            test_snmpv3_config.JSON_MISSING_ENGINE +
            test_snmpv3_config.JSON_END
            )
        tds.c_config = json.loads(pconfig)

        snmp_engine = engine.SnmpEngine()
        rconfig, rsnmp_engine = trapd_snmpv3.load_snmpv3_credentials(config, snmp_engine, tds.c_config)
        self.assertEqual(rsnmp_engine, snmp_engine)


if __name__ == "__main__": # pragma: no cover
    unittest.main()
