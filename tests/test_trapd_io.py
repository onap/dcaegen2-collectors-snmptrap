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

import datetime
import glob
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import snmptrapd
import trapd_settings as tds
import trapd_runtime_pid
import trapd_io


# @unittest.skip("DONE")
class test_trapd_io(unittest.TestCase):
    """
    Test the save_pid mod
    """

    class PseudoFile():
        """ test file-like object that does nothing """
        def write(self):
            pass
        def close(self):
            pass

    class WriteThrows():
        """ test file-like object that throws on a write """
        def write(self):
            raise RuntimeError("close() throws")


    @classmethod
    def setUpClass(cls):

        tds.init()

        snmptrap_dir = "/tmp/opt/app/snmptrap"
        try:
            Path(snmptrap_dir + "/logs").mkdir(parents=True, exist_ok=True)
            Path(snmptrap_dir + "/tmp").mkdir(parents=True, exist_ok=True)
            Path(snmptrap_dir + "/etc").mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print("Error while running %s : %s" % (os.path.basename(__file__), str(e.strerror)))
            sys.exit(1)

        # fmt: off
        tds.c_config = json.loads(
            '{ "snmptrapd": { '
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
        tds.json_traps_filename = (
            tds.c_config["files"]["runtime_base_dir"] + "/json_traps.json"
        )
        tds.arriving_traps_filename = (
            tds.c_config["files"]["runtime_base_dir"] + "/arriving_traps.log"
        )


    def test_open_eelf_error_file(self):
        """
        Test bad error file location
        """

        with patch.dict(tds.c_config["files"]):
            # open eelf error logs
            tds.c_config["files"]["eelf_error"] = "/bad_dir/error.log"

            # try to open file in non-existent dir
            with self.assertRaises(SystemExit):
                result = trapd_io.open_eelf_logs()


    def test_open_eelf_debug_file(self):
        """
        Test bad debug file location
        """

        # open eelf debug logs
        with patch.dict(tds.c_config["files"]):
            tds.c_config["files"]["eelf_debug"] = "/bad_dir/debug.log"

            # try to open file in non-existent dir
            with self.assertRaises(SystemExit):
                result = trapd_io.open_eelf_logs()


    def test_open_eelf_audit_file(self):
        """
        Test bad audit file location
        """

        with patch.dict(tds.c_config["files"]):
            # open eelf debug logs
            tds.c_config["files"]["eelf_audit"] = "/bad_dir/audit.log"

            # try to open file in non-existent dir
            with self.assertRaises(SystemExit):
                result = trapd_io.open_eelf_logs()


    def test_open_eelf_metrics_file(self):
        """
        Test bad metrics file location
        """

        with patch.dict(tds.c_config["files"]):
            # open eelf debug logs
            tds.c_config["files"]["eelf_metrics"] = "/bad_dir/metrics.log"

            # try to open file in non-existent dir
            with self.assertRaises(SystemExit):
                result = trapd_io.open_eelf_logs()


    def test_open_eelf_error_file_missing_name(self):
        """
        Test bad error file location
        """

        with patch.dict(tds.c_config["files"]):
            # open eelf error logs
            del tds.c_config["files"]["eelf_error"]

            # try to open file in non-existent dir
            with self.assertRaises(SystemExit):
                result = trapd_io.open_eelf_logs()


    def test_open_eelf_debug_file_missing_name(self):
        """
        Test bad debug file location
        """

        # open eelf debug logs
        with patch.dict(tds.c_config["files"]):
            del tds.c_config["files"]["eelf_debug"]

            # try to open file in non-existent dir
            with self.assertRaises(SystemExit):
                result = trapd_io.open_eelf_logs()


    def test_open_eelf_audit_file_missing_name(self):
        """
        Test bad audit file location
        """

        with patch.dict(tds.c_config["files"]):
            # open eelf debug logs
            del tds.c_config["files"]["eelf_audit"]

            # try to open file in non-existent dir
            with self.assertRaises(SystemExit):
                result = trapd_io.open_eelf_logs()


    def test_open_eelf_metrics_file_missing_name(self):
        """
        Test bad metrics file location
        """

        with patch.dict(tds.c_config["files"]):
            # open eelf debug logs
            del tds.c_config["files"]["eelf_metrics"]

            # try to open file in non-existent dir
            with self.assertRaises(SystemExit):
                result = trapd_io.open_eelf_logs()


    def test_roll_all_logs_not_open(self):
        """
        Test roll of logs when not open
        """

        # try to roll logs when not open. Shouldn't fail
        trapd_io.roll_all_logs()
        self.assertIsNotNone(tds.eelf_error_fd)

    def test_roll_all_logs(self):
        """
        Test rolling files that they are open
        """

        trapd_io.open_eelf_logs()
        # try to roll logs
        trapd_io.roll_all_logs()
        self.assertIsNotNone(tds.eelf_error_fd)


    def test_roll_all_logs_roll_file_throws(self):
        """
        Test rolling files that they are open
        but roll_file throws an exception
        """

        trapd_io.open_eelf_logs()
        # try to roll logs
        with patch('trapd_io.roll_file') as roll_file_throws:
            roll_file_throws.side_effect = RuntimeError("roll_file() throws")
            with self.assertRaises(SystemExit):
                trapd_io.roll_all_logs()
                self.assertIsNotNone(tds.eelf_error_fd)


    def test_roll_all_logs_open_eelf_logs_returns_false(self):
        """
        Test rolling files that they are open
        but open_eelf_logs returns false
        """

        trapd_io.open_eelf_logs()
        # try to roll logs
        with patch('trapd_io.open_eelf_logs') as open_eelf_logs_throws:
            open_eelf_logs_throws.return_value = False
            with self.assertRaises(SystemExit):
                trapd_io.roll_all_logs()
                self.assertIsNotNone(tds.eelf_error_fd)


    def test_roll_all_logs_open_file_json_traps_throws(self):
        """
        Test rolling files that they are open
        but open_file(json_traps_filename) throws an exception
        """

        def tmp_func(nm):
            if nm == tds.json_traps_filename:
                raise RuntimeError("json_traps_filename throws")
            return test_trapd_io.PseudoFile()

        trapd_io.open_eelf_logs()
        # try to roll logs
        with patch('trapd_io.open_file') as open_file_throws:
            open_file_throws.side_effect = tmp_func
            with self.assertRaises(SystemExit):
                trapd_io.roll_all_logs()
                self.assertIsNotNone(tds.eelf_error_fd)


    def test_roll_all_logs_open_file_arriving_traps_throws(self):
        """
        Test rolling files that they are open
        but open_file(arriving_traps_filename) throws an exception
        """

        def tmp_func(nm):
            if nm == tds.arriving_traps_filename:
                raise RuntimeError("arriving_traps_filename throws")
            return test_trapd_io.PseudoFile()

        trapd_io.open_eelf_logs()
        # try to roll logs
        with patch('trapd_io.open_file') as open_file_throws:
            open_file_throws.side_effect = tmp_func
            with self.assertRaises(SystemExit):
                trapd_io.roll_all_logs()
                self.assertIsNotNone(tds.eelf_error_fd)


    def test_roll_file(self):
        """
        Test roll of individual file when not present
        """

        # try to roll a valid log file
        with tempfile.TemporaryDirectory() as ntd:
            fn = ntd + "/test.log"
            with open(fn, "w") as ofp:
                self.assertTrue(trapd_io.roll_file(fn))
                # The file will be renamed to something like
                # test.log.2022-08-17T20:28:32
                self.assertFalse(os.path.exists(fn))
                # We could also add a test to see if there is a file
                # with a name like that.
                files = list(glob.glob(f"{ntd}/*"))
                print(f"files={files}")
                self.assertEqual(len(files), 1)
                self.assertTrue(files[0].startswith(fn + "."))


    def test_roll_file_not_present(self):
        """
        Test roll of individual file when not present
        """

        # try to roll logs when not open
        self.assertFalse(trapd_io.roll_file("/file/not/present"))


    def test_roll_file_no_write_perms(self):
        """
        try to roll logs when not enough perms
        """

        with tempfile.TemporaryDirectory() as no_perms_dir:
            # no_perms_dir = "/tmp/opt/app/snmptrap/no_perms"
            no_perms_file = "test.dat"
            no_perms_fp = no_perms_dir + "/" + no_perms_file

            # required directory tree
            #try:
            #    Path(no_perms_dir).mkdir(parents=True, exist_ok=True)
            #    os.chmod(no_perms_dir, 0o700)
            #except Exception as e:
            #    self.fail("Error while running %s : %s" % (os.path.basename(__file__), str(e.strerror)))

            # create empty file
            open(no_perms_fp, "w").close()
            os.chmod(no_perms_dir, 0o555)

            # try to roll file in dir with no write perms
            self.assertFalse(trapd_io.roll_file(no_perms_fp))

            # the file should still be there
            open(no_perms_fp).close()

            # allow the directory to be removed
            os.chmod(no_perms_dir, 0o700)


    def test_open_file_exists(self):
        """
        Test file open in directory present
        """

        # create copy of snmptrapd.json for pytest
        test_file = "/tmp/snmptrap_pytest"

        # try to roll logs when not open
        result = trapd_io.open_file(test_file)
        self.assertTrue(str(result).startswith("<_io.TextIOWrapper name="))
        self.assertIsInstance(result, io.TextIOWrapper)


    def test_open_file_exists_does_not_exist(self):
        """
        Test file open in directory present
        """

        # create copy of snmptrapd.json for pytest
        test_file = "/tmp/no_such_dir/snmptrap_pytest"

        # try to open file when dir not present
        with self.assertRaises(SystemExit):
            result = trapd_io.open_file(test_file)


    def test_close_file_exists(self):
        """
        Test closing a file that's present
        """

        # create copy of snmptrapd.json for pytest
        test_file_name = "/tmp/snmptrap_pytest"
        test_file = trapd_io.open_file(test_file_name)

        # close active file
        self.assertTrue(trapd_io.close_file(test_file, test_file_name))


    def test_close_file_does_not_exist(self):
        """
        Test closing non-existent file
        """

        # try to roll logs when not open
        self.assertFalse(trapd_io.close_file(None, None))


    def test_ecomp_logger_type_error(self):
        """
        test trapd_io.ecomp_logger
        """

        trapd_io.open_eelf_logs()
        msg = "this is a test"
        self.assertTrue(trapd_io.ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_ERROR, tds.CODE_GENERAL, msg))


    def test_ecomp_logger_type_error_bad_fd(self):
        """
        test trapd_io.ecomp_logger, but write() throws
        """

        trapd_io.open_eelf_logs()
        msg = "this is a test"
        # the following SHOULD be done with a context patch
        sv_eelf_error_fd = tds.eelf_error_fd
        tds.eelf_error_fd = test_trapd_io.WriteThrows()
        self.assertTrue(trapd_io.ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_ERROR, tds.CODE_GENERAL, msg))
        tds.eelf_error_fd = sv_eelf_error_fd


    def test_ecomp_logger_type_unknown_bad_fd(self):
        """
        test trapd_io.ecomp_logger, unknown type, but write() throws
        """

        trapd_io.open_eelf_logs()
        msg = "this is a test"
        # the following SHOULD be done with a context patch
        sv_eelf_error_fd = tds.eelf_error_fd
        tds.eelf_error_fd = test_trapd_io.WriteThrows()
        self.assertFalse(trapd_io.ecomp_logger(-1, tds.SEV_ERROR, tds.CODE_GENERAL, msg))
        tds.eelf_error_fd = sv_eelf_error_fd


    def test_ecomp_logger_type_metrics(self):
        """
        test trapd_io.ecomp_logger to metrics
        """

        trapd_io.open_eelf_logs()
        msg = "this is a test"
        self.assertTrue(trapd_io.ecomp_logger(tds.LOG_TYPE_METRICS, tds.SEV_ERROR, tds.CODE_GENERAL, msg))


    def test_ecomp_logger_type_metrics_bad_fd(self):
        """
        test trapd_io.ecomp_logger to metrics, but write() throws
        """

        trapd_io.open_eelf_logs()
        msg = "this is a test"
        # the following SHOULD be done with a context patch
        sv_eelf_metrics_fd = tds.eelf_metrics_fd
        tds.eelf_metrics_fd = test_trapd_io.WriteThrows()
        self.assertTrue(trapd_io.ecomp_logger(tds.LOG_TYPE_METRICS, tds.SEV_ERROR, tds.CODE_GENERAL, msg))
        tds.eelf_metrics_fd = sv_eelf_metrics_fd


    def test_ecomp_logger_type_audit(self):
        """
        test trapd_io.ecomp_logger to audit log
        """

        trapd_io.open_eelf_logs()
        msg = "this is a test"
        self.assertTrue(trapd_io.ecomp_logger(tds.LOG_TYPE_AUDIT, tds.SEV_ERROR, tds.CODE_GENERAL, msg))


    def test_ecomp_logger_type_audit_bad_fd(self):
        """
        test trapd_io.ecomp_logger to audit log, but write() throws
        """

        trapd_io.open_eelf_logs()
        msg = "this is a test"
        # the following SHOULD be done with a context patch
        sv_eelf_audit_fd = tds.eelf_audit_fd
        tds.eelf_audit_fd = test_trapd_io.WriteThrows()
        self.assertTrue(trapd_io.ecomp_logger(tds.LOG_TYPE_AUDIT, tds.SEV_ERROR, tds.CODE_GENERAL, msg))
        tds.eelf_audit_fd = sv_eelf_audit_fd


    def test_ecomp_logger_type_unknown(self):
        """
        test trapd_io.ecomp_logger
        """

        trapd_io.open_eelf_logs()
        msg = "this is a test"
        self.assertFalse(trapd_io.ecomp_logger(-1, tds.SEV_ERROR, tds.CODE_GENERAL, msg))


if __name__ == "__main__": # pragma: no cover
    unittest.main()
