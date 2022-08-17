# ============LICENSE_START=======================================================
# Copyright (c) 2018-2022 AT&T Intellectual Property. All rights reserved.
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

import copy
import datetime
import os
import unittest
from pathlib import Path
import time
from unittest.mock import patch, Mock

import requests

import snmptrapd

import trapd_settings as tds
import trapd_stormwatch_settings as sws
import trapd_stormwatch as sw
import trapd_http_session
import trapd_runtime_pid
import trapd_io
import trapd_get_cbs_config

from pysnmp.hlapi import *
from pysnmp import debug


# @unittest.skip("DONE")
class test_snmptrapd(unittest.TestCase):
    """
    Test the save_pid mod
    """

    class WriteThrows():
        def write():
            raise RuntimeError("write() throws")


    @classmethod
    def setUpClass(cls):

        # init vars
        tds.init()
        sw.sw_init()

        # fmt: off
        test_snmptrapd.pytest_empty_data = "{}"
        test_snmptrapd.pytest_json_data = (
            '{ "snmptrapd": { '
            '        "version": "2.0.3", '
            '        "title": "ONAP SNMP Trap Receiver" }, '
            '    "protocols": { '
            '        "transport": "udp", '
            '        "ipv4_interface": "0.0.0.0", '
            '        "ipv4_port": 6162, '
            '        "ipv6_interface": "::1", '
            '        "ipv6_port": 6162 }, '
            '    "cache": { '
            '        "dns_cache_ttl_seconds": 60 }, '
            '    "publisher": { '
            '        "http_timeout_milliseconds": 1500, '
            '        "http_retries": 3, '
            '        "http_milliseconds_between_retries": 750, '
            '        "http_primary_publisher": "true", '
            '        "http_peer_publisher": "unavailable", '
            '        "max_traps_between_publishes": 10, '
            '        "max_milliseconds_between_publishes": 10000 }, '
            '    "streams_publishes": { '
            '        "sec_fault_unsecure": { '
            '            "type": "message_router", '
            '            "aaf_password": null, '
            '            "dmaap_info": { '
            '                "location": "mtl5", '
            '                "client_id": null, '
            '                "client_role": null, '
            '                "topic_url": "http://uebsb91kcdc.it.att.com:3904/events/ONAP-COLLECTOR-SNMPTRAP" }, '
            '            "aaf_username": null } }, '
            '    "files": { '
            '        "runtime_base_dir": "/tmp/opt/app/snmptrap", '
            '        "log_dir": "logs", '
            '        "data_dir": "data", '
            '        "pid_dir": "tmp", '
            '        "arriving_traps_log": "snmptrapd_arriving_traps.log", '
            '        "snmptrapd_diag": "snmptrapd_prog_diag.log", '
            '        "traps_stats_log": "snmptrapd_stats.csv", '
            '        "perm_status_file": "snmptrapd_status.log", '
            '        "eelf_base_dir": "/tmp/opt/app/snmptrap/logs", '
            '        "eelf_error": "error.log", '
            '        "eelf_debug": "debug.log", '
            '        "eelf_audit": "audit.log", '
            '        "eelf_metrics": "metrics.log", '
            '        "roll_frequency": "day", '
            '        "minimum_severity_to_log": 2 }, '
            '    "trap_config": { '
            '        "sw_interval_in_seconds": 60, '
            '        "notify_oids": { '
            '            ".1.3.6.1.4.1.9.0.1": { '
            '                "sw_high_water_in_interval": 102, '
            '                "sw_low_water_in_interval": 7, '
            '                "category": "logonly" }, '
            '            ".1.3.6.1.4.1.9.0.2": { '
            '                "sw_high_water_in_interval": 101, '
            '                "sw_low_water_in_interval": 7, '
            '                "category": "logonly" }, '
            '            ".1.3.6.1.4.1.9.0.3": { '
            '                "sw_high_water_in_interval": 102, '
            '                "sw_low_water_in_interval": 7, '
            '                "category": "logonly" }, '
            '            ".1.3.6.1.4.1.9.0.4": { '
            '                "sw_high_water_in_interval": 10, '
            '                "sw_low_water_in_interval": 3, '
            '                "category": "logonly" } } }, '
            '    "snmpv3_config": { '
            '        "usm_users": [ { '
            '            "user": "usr-sha-aes256", '
            '            "engineId": "8000000001020304", '
            '            "usmHMACSHAAuth": "authkey1", '
            '            "usmAesCfb256": "privkey1" }, '
            '        { "user": "user1", '
            '            "engineId": "8000000000000001", '
            '            "usmHMACMD5Auth": "authkey1", '
            '            "usmDESPriv": "privkey1" }, '
            '        { "user": "user2", '
            '            "engineId": "8000000000000002", '
            '            "usmHMACSHAAuth": "authkey2", '
            '            "usmAesCfb128": "privkey2" }, '
            '        { "user": "user3", '
            '            "engineId": "8000000000000003", '
            '            "usmHMACSHAAuth": "authkey3", '
            '            "usmAesCfb256": "privkey3" } '
            '    ] } }'
            )
        # fmt: off

        test_snmptrapd.trap_dict_info = {
            "uuid": "06f6e91c-3236-11e8-9953-005056865aac",
            "agent address": "1.2.3.4",
            "agent name": "test-agent.nodomain.com",
            "cambria.partition": "test-agent.nodomain.com",
            "community": "",
            "community len": 0,
            "epoch_serno": 15222068260000,
            "protocol version": "v2c",
            "time received": 1522206826.2938566,
            "trap category": "ONAP-COLLECTOR-SNMPTRAP",
            "sysUptime": "218567736",
            "notify OID": "1.3.6.1.4.1.9999.9.9.999",
            "notify OID len": 10,
        }

        snmptrap_dir = "/tmp/opt/app/snmptrap"
        try:
            Path(snmptrap_dir + "/logs").mkdir(parents=True, exist_ok=True)
            Path(snmptrap_dir + "/tmp").mkdir(parents=True, exist_ok=True)
            Path(snmptrap_dir + "/etc").mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print("Error while running %s : %s" % (os.path.basename(__file__), str(e.strerror)))
            sys.exit(1)

        # create copy of snmptrapd.json for pytest
        test_snmptrapd.pytest_json_config = "/tmp/opt/app/snmptrap/etc/snmptrapd.json"
        with open(test_snmptrapd.pytest_json_config, "w") as outfile:
            outfile.write(test_snmptrapd.pytest_json_data)

        test_snmptrapd.pytest_empty_config = "/tmp/opt/app/snmptrap/etc/empty.json"
        with open(test_snmptrapd.pytest_empty_config, "w") as outfile:
            outfile.write(test_snmptrapd.pytest_empty_data)


    def test_usage_err(self):
        """
        Test usage error
        """

        with self.assertRaises(SystemExit) as exc:
            snmptrapd.usage_err()
        self.assertEqual(str(exc.exception), "1")


    def test_load_all_configs(self):
        """
        Test load of all configs
        """
        # request load of CBS data
        with patch.dict(os.environ, {'CBS_SIM_JSON':test_snmptrapd.pytest_json_config}):
            self.assertEqual(os.getenv('CBS_SIM_JSON'), test_snmptrapd.pytest_json_config)

            result = trapd_get_cbs_config.get_cbs_config()
            self.assertEqual(result, True)

            # request load of CBS data
            self.assertEqual(snmptrapd.load_all_configs(0, 1), True)


    def test_resolve_ip(self):
        """ Test resolve_ip """
        with patch.dict(os.environ, {'CBS_SIM_JSON':test_snmptrapd.pytest_json_config}):
            self.assertEqual(os.getenv('CBS_SIM_JSON'), test_snmptrapd.pytest_json_config)

            time_base = 1000000
            time_offset = 10000
            with patch('time.time', return_value=time_base):
                self.assertEqual(time.time(), time_base)

                fqdn = "foo.example"
                ip = "1.2.3.4"
                with patch.dict(tds.dns_cache_ip_to_name):
                    tds.dns_cache_ip_to_name = { }
                    # DOUBLE EXCEPTION - nothing in tds.dns_cache_ip_expires
                    # and gethostbyaddr() fails
                    with patch('socket.gethostbyaddr', side_effect=RuntimeError("gethostbyaddr raises")):
                        self.assertEqual(snmptrapd.resolve_ip(ip), ip)
                        self.assertEqual(tds.dns_cache_ip_to_name[ip], ip)
                        self.assertEqual(tds.dns_cache_ip_expires[ip], time_base + 60)

                    tds.dns_cache_ip_to_name = { ip: fqdn }
                    with patch('socket.gethostbyaddr', return_value=(fqdn,fqdn,[ip])):
                        # EXCEPTION - nothing in tds.dns_cache_ip_expires
                        del tds.dns_cache_ip_expires[ip]
                        self.assertEqual(snmptrapd.resolve_ip(ip), fqdn)
                        self.assertEqual(tds.dns_cache_ip_to_name[ip], fqdn)
                        self.assertEqual(tds.dns_cache_ip_expires[ip], time_base + 60)

                        with patch.dict(tds.dns_cache_ip_expires, {ip: time.time() - 10000}):
                            self.assertEqual(snmptrapd.resolve_ip(ip), fqdn)
                            self.assertEqual(tds.dns_cache_ip_to_name[ip], fqdn)
                            self.assertEqual(tds.dns_cache_ip_expires[ip], time_base + 60)


                        with patch.dict(tds.dns_cache_ip_expires, {ip: time.time() + 10000}):
                            self.assertEqual(snmptrapd.resolve_ip(ip), fqdn)
                            self.assertEqual(tds.dns_cache_ip_to_name[ip], fqdn)
                            self.assertEqual(tds.dns_cache_ip_expires[ip], time_base + time_offset)


    def test_load_all_configs_signal(self):
        """
        Test load of all configs via runtime signal
        """

        # init vars
        tds.init()

        # request load of CBS data
        with patch.dict(os.environ, {'CBS_SIM_JSON':test_snmptrapd.pytest_json_config}):
            self.assertEqual(os.getenv('CBS_SIM_JSON'), test_snmptrapd.pytest_json_config)

            self.assertTrue(trapd_get_cbs_config.get_cbs_config())

            # request load of CBS data
            self.assertTrue(snmptrapd.load_all_configs(1, 1))

            with patch('snmptrapd.get_cbs_config', return_value=False):
                with self.assertRaises(SystemExit):
                    snmptrapd.load_all_configs(1, 1)


    def test_log_all_arriving_traps(self):
        """
        Test logging of traps
        """
        # init vars
        tds.init()

        # don't open files, but try to log - should raise exception
        with self.assertRaises(Exception) as exc:
            snmptrapd.log_all_arriving_traps()
        self.assertIsInstance(exc.exception, TypeError)

        # request load of CBS data
        with patch.dict(os.environ, {'CBS_SIM_JSON':test_snmptrapd.pytest_json_config}):
            # trap dict for logging
            with patch.dict(tds.trap_dict, copy.deepcopy(test_snmptrapd.trap_dict_info)):
                self.assertEqual(os.getenv('CBS_SIM_JSON'), test_snmptrapd.pytest_json_config)

                result = trapd_get_cbs_config.get_cbs_config()

                # set last day to current
                tds.last_day = datetime.datetime.now().day


                # open eelf logs
                trapd_io.open_eelf_logs()

                # open trap logs
                tds.arriving_traps_filename = (
                    tds.c_config["files"]["runtime_base_dir"]
                    + "/"
                    + tds.c_config["files"]["log_dir"]
                    + "/"
                    + (tds.c_config["files"]["arriving_traps_log"])
                )
                tds.arriving_traps_fd = trapd_io.open_file(tds.arriving_traps_filename)

                # name and open json trap log
                tds.json_traps_filename = (
                    tds.c_config["files"]["runtime_base_dir"]
                    + "/"
                    + tds.c_config["files"]["log_dir"]
                    + "/"
                    + "DMAAP_"
                    + (tds.c_config["streams_publishes"]["sec_fault_unsecure"]["dmaap_info"]["topic_url"].split("/")[-1])
                    + ".json"
                )
                tds.json_traps_fd = trapd_io.open_file(tds.json_traps_filename)
                msg = "published traps logged to: %s" % tds.json_traps_filename
                trapd_io.stdout_logger(msg)
                trapd_io.ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
                # also force it to daily roll
                snmptrapd.log_all_arriving_traps()

                # try again, but with day rolling
                tds.last_day = datetime.datetime.now().day - 1
                snmptrapd.log_all_arriving_traps()

                # try again, with roll_frequency set to minute
                tds.last_minute = datetime.datetime.now().minute - 1
                tds.c_config["files"]["roll_frequency"] = "minute"
                snmptrapd.log_all_arriving_traps()

                # try again, with roll_frequency set to hour
                tds.last_hour = datetime.datetime.now().hour - 1
                tds.c_config["files"]["roll_frequency"] = "hour"
                snmptrapd.log_all_arriving_traps()

                # try again, with a bad trap_dict[time_received]
                tds.trap_dict["time received"] = "bad_value"
                snmptrapd.log_all_arriving_traps()

                # also test log_published_messages()
                snmptrapd.log_published_messages("data #1")

                # work even if there is an exception
                # this SHOULD be done with a context
                sv_json_traps_fd = tds.json_traps_fd
                tds.json_traps_fd = test_snmptrapd.WriteThrows()
                snmptrapd.log_published_messages("data #2")
                tds.json_traps_fd = sv_json_traps_fd


    def test_log_all_incorrect_log_type(self):
        """
        Test logging of traps
        """

        # init vars
        tds.init()

        # request load of CBS data
        with patch.dict(os.environ, {'CBS_SIM_JSON':test_snmptrapd.pytest_json_config}):
            self.assertEqual(os.getenv('CBS_SIM_JSON'), test_snmptrapd.pytest_json_config)

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
        with patch.dict(os.environ, {'CBS_SIM_JSON':test_snmptrapd.pytest_json_config}):
            self.assertEqual(os.getenv('CBS_SIM_JSON'), test_snmptrapd.pytest_json_config)

            trapd_get_cbs_config.get_cbs_config()

            errorIndication, errorStatus, errorIndex, varbinds = next(
                sendNotification(
                    SnmpEngine(),
                    CommunityData("not_public"),
                    UdpTransportTarget(("localhost", 6162)),
                    ContextData(),
                    "trap",
                    [
                        ObjectType(ObjectIdentity(".1.3.6.1.4.1.999.1"), OctetString("test trap - ignore")),
                        ObjectType(ObjectIdentity(".1.3.6.1.4.1.999.2"), OctetString("ONAP pytest trap")),
                    ],
                )
            )

            result = errorIndication
            self.assertEqual(result, None)


    def test_post_dmaap(self):
        """
        Test post_dmaap()
        """

        # trap dict for logging
        with patch.dict(tds.trap_dict, copy.deepcopy(test_snmptrapd.trap_dict_info)):
            with patch('snmptrapd.ecomp_logger') as magic_ecomp_logger:
                with patch('requests.Session.post') as magic_session_post:
                    fake_post_resp = Mock()
                    magic_session_post.return_value = fake_post_resp

                    fake_post_resp.status_code = requests.codes.moved_permanently
                    snmptrapd.post_dmaap()
                    self.assertEqual(magic_ecomp_logger.call_count, 11)

                    fake_post_resp.status_code = requests.codes.ok
                    snmptrapd.post_dmaap()
                    self.assertEqual(magic_ecomp_logger.call_count, 16)

                    magic_ecomp_logger.call_count = 0
                    tds.traps_since_last_publish = 1
                    snmptrapd.post_dmaap()
                    self.assertEqual(magic_ecomp_logger.call_count, 5)

                    magic_ecomp_logger.call_count = 0
                    tds.c_config["streams_publishes"]["sec_fault_unsecure"]["aaf_username"] = "aaf_username"
                    tds.c_config["streams_publishes"]["sec_fault_unsecure"]["aaf_password"] = "aaf_password"
                    snmptrapd.post_dmaap()
                    self.assertEqual(magic_ecomp_logger.call_count, 5)

                    # for some reason this exception is being seen as an OSError ????
                    magic_ecomp_logger.call_count = 0
                    magic_session_post.side_effect = requests.exceptions.RequestException("test throw")
                    snmptrapd.post_dmaap()
                    self.assertEqual(magic_ecomp_logger.call_count, 10)

                    magic_ecomp_logger.call_count = 0
                    magic_session_post.side_effect = OSError()
                    snmptrapd.post_dmaap()
                    self.assertEqual(magic_ecomp_logger.call_count, 10)


    @unittest.skip("do not know what to pass in for vars. Need an object with a clone() method")
    def test_comm_string_rewrite_observer(self):
        """
        test comm_string_rewrite_observer()
        """
        vars = { "communityName": ["name"] }
        snmptrapd.comm_string_rewrite_observer("snmpEngine", "execpoint", vars, "cbCtx")
        assertEqual(vars["communitName"], "public")

        vars = { "communityName": [] }
        snmptrapd.comm_string_rewrite_observer("snmpEngine", "execpoint", vars, "cbCtx")
        assertEqual(vars["communitName"], "")


    def test_snmp_engine_observer_cb(self):
        """
        test snmp_engine_observer_cb(snmp_engine, execpoint, variables, cbCtx):
        """

        snmp_engine = "snmp_engine"
        execpoint = "execpoint"
        cbCtx = "cbCtx"
        variables = {
            'transportDomain': [ 1, 2, 3 ],
            'transportAddress': [ "a", "b", "c" ]
        }
        for secmodel,ret in [ (1, "v1"), (2, "v2c"), (3, "v3"), (4, "unknown") ]:
            variables["securityModel"] = secmodel
            snmptrapd.snmp_engine_observer_cb(snmp_engine, execpoint, variables, cbCtx)
            self.assertEqual(tds.trap_dict["protocol version"], ret)


    def test_add_varbind_to_log_string(self):
        """
        test add_varbind_to_log_string(vb_idx, vb_oid, vb_type, vb_val)
        """
        vb_oid = "vb_oid"
        vb_type = "vb_type"

        class TempPP():
            def prettyPrint(self):
                return "pp ret"

        vb_val = TempPP()

        self.assertEqual(tds.all_vb_str, "")

        snmptrapd.add_varbind_to_log_string(0, vb_oid, vb_type, vb_val)
        self.assertEqual(tds.all_vb_str,
                         'varbinds: [0] vb_oid {vb_type} pp ret')

        snmptrapd.add_varbind_to_log_string(1, vb_oid, vb_type, vb_val)
        self.assertEqual(tds.all_vb_str,
                         'varbinds: [0] vb_oid {vb_type} pp ret [1] vb_oid {vb_type} pp ret')


    def test_add_varbind_to_json(self):
        """
        test add_varbind_to_json(vb_idx, vb_oid, vb_type, vb_val)
        """

        class TempPP():
            def __init__(self, ret):
                self.ret = ret
            def prettyPrint(self):
                return self.ret

        with patch.dict(tds.trap_dict, copy.deepcopy(test_snmptrapd.trap_dict_info)):
            vb_oid = TempPP("1.2.3")
            override_vb_oid = TempPP("1.3.6.1.6.3.18.1.3.0")

            vb_type = "vb_type"

            vb_val = TempPP("foo.example")

            self.assertEqual(snmptrapd.add_varbind_to_json(0, vb_oid, vb_type, vb_val), 0)
            self.assertEqual(snmptrapd.add_varbind_to_json(1, vb_oid, vb_type, vb_val), 0)
            self.assertEqual(tds.trap_dict["notify OID"], ".foo.example")
            self.assertEqual(tds.trap_dict["notify OID len"], 2)

            with patch('snmptrapd.resolve_ip') as magic_resolve_ip:
                magic_resolve_ip.return_value = 'foo.example'
                self.assertEqual(snmptrapd.add_varbind_to_json(2, override_vb_oid, vb_type, vb_val), 0)
                self.assertEqual(tds.trap_dict["agent address"], "foo.example")
                self.assertEqual(tds.trap_dict["agent name"], "foo.example")

                sv_protocol_version = tds.trap_dict["protocol version"]
                tds.trap_dict["protocol version"] = "v1"
                self.assertEqual(snmptrapd.add_varbind_to_json(4, vb_oid, vb_type, vb_val), 0)
                self.assertEqual(snmptrapd.add_varbind_to_json(5, vb_oid, vb_type, vb_val), 1)

                tds.trap_dict["protocol version"] = sv_protocol_version
                self.assertEqual(snmptrapd.add_varbind_to_json(6, vb_oid, vb_type, vb_val), 1)
                self.assertEqual(tds.all_vb_json_str,
                                 ', "varbinds": [{"varbind_oid": ".1.2.3", '
                                 '"varbind_type": "octet", "varbind_value": '
                                 '"foo.example"} ,{"varbind_oid": ".1.2.3", '
                                 '"varbind_type": "octet", "varbind_value": '
                                 '"foo.example"}')

                self.assertEqual(snmptrapd.add_varbind_to_json(7, vb_oid, vb_type, vb_val), 1)
                self.assertEqual(tds.all_vb_json_str,
                                 ', "varbinds": [{"varbind_oid": ".1.2.3", '
                                 '"varbind_type": "octet", "varbind_value": '
                                 '"foo.example"} ,{"varbind_oid": ".1.2.3", '
                                 '"varbind_type": "octet", "varbind_value": '
                                 '"foo.example"} ,{"varbind_oid": ".1.2.3", '
                                 '"varbind_type": "octet", "varbind_value": '
                                 '"foo.example"}')


    @patch('snmptrapd.log_all_arriving_traps')
    @patch('snmptrapd.post_dmaap', return_value = 0)
    @patch('snmptrapd.ecomp_logger', return_value = 0)
    @patch('snmptrapd.add_varbind_to_json', return_value = 1)
    @patch('snmptrapd.add_varbind_to_log_string', return_value = 0)
    def test_notif_receiver_cb(self, magic_add_varbind_to_log_string, magic_add_varbind_to_json,
                               magic_ecomp_logger, magic_port_dmaap, magic_lost_all_arriving_traps):
        """ notif_receiver_cb(snmp_engine, stateReference, contextEngineId, contextName, varBinds, cbCtx) """
        with patch.dict(tds.trap_dict, copy.deepcopy(test_snmptrapd.trap_dict_info)):
            with patch('trapd_stormwatch.sw_storm_active', return_value=True):
                snmptrapd.notif_receiver_cb("snmp_engine", "stateReference", "contextEngineId", "contextName", [("varBinds1", "varbinds2")], "cbCtx")
            with patch('trapd_stormwatch.sw_storm_active', return_value=False):
                snmptrapd.notif_receiver_cb("snmp_engine", "stateReference", "contextEngineId", "contextName", [("varBinds1", "varbinds2")], "cbCtx")
            self.assertFalse(tds.first_trap)
            self.assertEqual(magic_ecomp_logger.call_count, 8)

            magic_ecomp_logger.call_count = 0
            with patch('trapd_stormwatch.sw_storm_active', return_value=False):
                snmptrapd.notif_receiver_cb("snmp_engine", "stateReference", "contextEngineId", "contextName", [("varBinds1", "varbinds2")], "cbCtx")
                self.assertEqual(magic_ecomp_logger.call_count, 4)

            magic_ecomp_logger.call_count = 0
            tds.c_config["publisher"]["max_traps_between_publishes"] = 1
            with patch('trapd_stormwatch.sw_storm_active', return_value=False):
                snmptrapd.notif_receiver_cb("snmp_engine", "stateReference", "contextEngineId", "contextName", [("varBinds1", "varbinds2")], "cbCtx")
                self.assertEqual(magic_ecomp_logger.call_count, 4)

            magic_ecomp_logger.call_count = 0
            tds.c_config["publisher"]["max_traps_between_publishes"] = 100
            tds.c_config["publisher"]["max_milliseconds_between_publishes"] = 0
            tds.last_pub_time = 0
            with patch('time.time', return_value=0):
                with patch('trapd_stormwatch.sw_storm_active', return_value=False):
                    snmptrapd.notif_receiver_cb("snmp_engine", "stateReference", "contextEngineId", "contextName", [("varBinds1", "varbinds2")], "cbCtx")
                    self.assertEqual(magic_ecomp_logger.call_count, 4)

            magic_ecomp_logger.call_count = 0
            tds.last_pub_time = 100000
            tds.c_config["publisher"]["max_milliseconds_between_publishes"] = 1
            with patch('time.time', return_value=10):
                with patch('trapd_stormwatch.sw_storm_active', return_value=False):
                    snmptrapd.notif_receiver_cb("snmp_engine", "stateReference", "contextEngineId", "contextName", [("varBinds1", "varbinds2")], "cbCtx")
                    self.assertEqual(magic_ecomp_logger.call_count, 4)


if __name__ == "__main__": # pragma: no cover
    unittest.main()
