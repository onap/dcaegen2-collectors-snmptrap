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
    tds.c_config = json.loads("{ \"snmptrapd\": { \"version\": \"1.4.0\", \"title\": \"ONAP SNMP Trap Receiver\" }, \"protocols\": { \"transport\": \"udp\", \"ipv4_interface\": \"0.0.0.0\", \"ipv4_port\": 6162, \"ipv6_interface\": \"::1\", \"ipv6_port\": 6162 }, \"cache\": { \"dns_cache_ttl_seconds\": 60 }, \"publisher\": { \"http_timeout_milliseconds\": 1500, \"http_retries\": 3, \"http_milliseconds_between_retries\": 750, \"http_primary_publisher\": \"true\", \"http_peer_publisher\": \"unavailable\", \"max_traps_between_publishes\": 10, \"max_milliseconds_between_publishes\": 10000 }, \"streams_publishes\": { \"sec_fault_unsecure\": { \"type\": \"message_router\", \"aaf_password\": null, \"dmaap_info\": { \"location\": \"mtl5\", \"client_id\": null, \"client_role\": null, \"topic_url\": \"http://localhost:3904/events/ONAP-COLLECTOR-SNMPTRAP\" }, \"aaf_username\": null } }, \"files\": { \"runtime_base_dir\": \"/tmp/opt/app/snmptrap\", \"log_dir\": \"logs\", \"data_dir\": \"data\", \"pid_dir\": \"tmp\", \"arriving_traps_log\": \"snmptrapd_arriving_traps.log\", \"snmptrapd_diag\": \"snmptrapd_prog_diag.log\", \"traps_stats_log\": \"snmptrapd_stats.csv\", \"perm_status_file\": \"snmptrapd_status.log\", \"eelf_base_dir\": \"/tmp/opt/app/snmptrap/logs\", \"eelf_error\": \"error.log\", \"eelf_debug\": \"debug.log\", \"eelf_audit\": \"audit.log\", \"eelf_metrics\": \"metrics.log\", \"roll_frequency\": \"day\", \"minimum_severity_to_log\": 2 }, \"trap_config\": { \"sw_interval_in_seconds\": 60, \"notify_oids\": { \".1.3.6.1.4.1.9.0.1\": { \"sw_high_water_in_interval\": 102, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.2\": { \"sw_high_water_in_interval\": 101, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.3\": { \"sw_high_water_in_interval\": 102, \"sw_low_water_in_interval\": 7, \"category\": \"logonly\" }, \".1.3.6.1.4.1.9.0.4\": { \"sw_high_water_in_interval\": 10, \"sw_low_water_in_interval\": 3, \"category\": \"logonly\" } } }, \"snmpv3_config\": { \"usm_users\": [ { \"user\": \"usr-sha-aes256\", \"engineId\": \"8000000001020304\", \"usmHMACSHAAuth\": \"authkey1\", \"usmAesCfb256\": \"privkey1\" }, { \"user\": \"user1\", \"engineId\": \"8000000000000001\", \"usmHMACMD5Auth\": \"authkey1\", \"usmDESPriv\": \"privkey1\" }, { \"user\": \"user2\", \"engineId\": \"8000000000000002\", \"usmHMACSHAAuth\": \"authkey2\", \"usmAesCfb128\": \"privkey2\" }, { \"user\": \"user3\", \"engineId\": \"8000000000000003\", \"usmHMACSHAAuth\": \"authkey3\", \"usmAesCfb256\": \"privkey3\" } ] } }")
    post_data_enclosed=json.loads("[{\"epoch_serno\": 15488041460000, \"uuid\": \"bd3a87a0-241c-11e9-ac41-0242ac11000f\", \"agent address\": \"127.0.0.1\", \"agent name\": \"localhost\", \"cambria.partition\": \"localhost\", \"community\": \"\", \"community len\": 0, \"protocol version\": \"v2c\", \"time received\": 1548804146, \"trap category\": \"com.att.dcae.dmaap.FTL.24256-DCAE-COLLECTOR-UCSNMP-v1\", \"notify OID\": \".1.3.6.1.4.1.74.2.46.12.1.1\", \"notify OID len\": 12, \"varbinds\": [{\"varbind_oid\": \".1.3.6.1.4.1.74.2.46.12.1.1.1\", \"varbind_type\": \"octet\", \"varbind_value\": \"ucsnmp heartbeat - ignore\"} ,{\"varbind_oid\": \".1.3.6.1.4.1.74.2.46.12.1.1.2\", \"varbind_type\": \"octet\", \"varbind_value\": \"Tue Jan 29 23:22:26 2019\"}]}, {\"epoch_serno\": 15488041560000, \"uuid\": \"c338a4b6-241c-11e9-ac41-0242ac11000f\", \"agent address\": \"127.0.0.1\", \"agent name\": \"localhost\", \"cambria.partition\": \"localhost\", \"community\": \"\", \"community len\": 0, \"protocol version\": \"v2c\", \"time received\": 1548804156, \"trap category\": \"com.att.dcae.dmaap.FTL.24256-DCAE-COLLECTOR-UCSNMP-v1\", \"notify OID\": \".1.3.6.1.4.1.74.2.46.12.1.1\", \"notify OID len\": 12, \"varbinds\": [{\"varbind_oid\": \".1.3.6.1.4.1.74.2.46.12.1.1.1\", \"varbind_type\": \"octet\", \"varbind_value\": \"ucsnmp heartbeat - ignore\"} ,{\"varbind_oid\": \".1.3.6.1.4.1.74.2.46.12.1.1.2\", \"varbind_type\": \"octet\", \"varbind_value\": \"Tue Jan 29 23:22:36 2019\"}]}]")


def test_open_eelf_error_file():
    """
    Test bad error file location
    """

    # open eelf error logs
    tds.c_config['files.eelf_error']="/bad_dir/error.log"

    # try to open file in non-existent dir
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        result = trapd_io.open_eelf_logs()
        assert pytest_wrapped_exception.type == SystemExit

def test_open_eelf_debug_file():
    """
    Test bad debug file location
    """

    # open eelf debug logs
    tds.c_config['files.eelf_debug']="/bad_dir/debug.log"

    # try to open file in non-existent dir
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        result = trapd_io.open_eelf_logs()
        assert pytest_wrapped_exception.type == SystemExit

def test_open_eelf_audit_file():
    """
    Test bad audit file location
    """

    # open eelf debug logs
    tds.c_config['files.eelf_audit']="/bad_dir/audit.log"

    # try to open file in non-existent dir
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        result = trapd_io.open_eelf_logs()
        assert pytest_wrapped_exception.type == SystemExit

def test_open_eelf_metrics_file():
    """
    Test bad metrics file location
    """

    # open eelf debug logs
    tds.c_config['files.eelf_metrics']="/bad_dir/metrics.log"

    # try to open file in non-existent dir
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        result = trapd_io.open_eelf_logs()
        assert pytest_wrapped_exception.type == SystemExit

def test_roll_all_logs():
    """
    Test roll of logs when not open
    """

    # try to roll logs when not open
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        result = trapd_io.roll_all_logs()
        assert pytest_wrapped_exception.type == SystemExit

def test_roll_file():
    """
    Test roll of individual file when not present
    """

    # try to roll logs when not open
    assert trapd_io.roll_file("/file/not/present") == False

def test_open_file_exists():
    """
    Test file open in directory present
    """

    # create copy of snmptrapd.json for pytest
    test_file = "/tmp/snmptrap_pytest"

    # try to roll logs when not open
    result = trapd_io.open_file(test_file)
    assert str(result).startswith("<_io.TextIOWrapper name=") == True


def test_open_file_exists_does_not_exist():
    """
    Test file open in directory present
    """

    # create copy of snmptrapd.json for pytest
    test_file = "/tmp/no_such_dir/snmptrap_pytest"

    # try to open file when dir not present
    with pytest.raises(SystemExit) as pytest_wrapped_exception:
        result = trapd_io.open_file(test_file)
        assert pytest_wrapped_exception.type == SystemExit

def test_close_file_exists():
    """
    Test closing a file that's present
    """

    # create copy of snmptrapd.json for pytest
    test_file_name = "/tmp/snmptrap_pytest"
    test_file = trapd_io.open_file(test_file_name)

    # close active file
    assert trapd_io.close_file(test_file, test_file_name) == True

def test_close_file_does_not_exists():
    """
    Test closing non-existent file 
    """

    # try to roll logs when not open
    assert trapd_io.close_file(None, None) == False
