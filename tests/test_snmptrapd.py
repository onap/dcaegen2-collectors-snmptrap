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
        os.environ.update(CBS_SIM_JSON='/opt/app/snmptrap/etc/snmptrapd.json')
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
        os.environ.update(CBS_SIM_JSON='/opt/app/snmptrap/etc/snmptrapd.json')
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
