# ============LICENSE_START=======================================================
# Copyright (c) 2020-2022 AT&T Intellectual Property. All rights reserved.
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

import unittest
import trapd_exit
import time
from unittest.mock import patch

import trapd_stormwatch as sw
import trapd_stormwatch_settings as sws
import trapd_stats_settings as stats
import trapd_settings as tds


# @unittest.skip("DONE")
class test_cleanup_and_exit(unittest.TestCase):
    """
    Test for presense of required vars
    """

    @classmethod
    def setUp(cls):
        tds.init()
        stats.init()
        sw.sw_init()
        sws.init()


    def test_sw_init(self):
        """ test sw_init() """
        sw.sw_init()
        self.assertEqual(sws.sw_interval_in_seconds, 60)
        sws.init()
        self.assertEqual(sws.sw_config_category, {})


    def test_sw_clear_dicts(self):
        """
        Test sw_clear_dicts
        """
        with patch.dict('trapd_stormwatch_settings.sw_storm_counter_dict'):
            with patch.dict('trapd_stormwatch_settings.sw_config_category'):
                with patch.dict('trapd_stats_settings.agent_counter_dict'):
                    with patch.dict('trapd_stats_settings.oid_counter_dict'):

                        # initialize attributes not handled by sw_init()
                        sws.sw_storm_counter_dict = {}
                        sws.sw_config_category = {}
                        stats.agent_counter_dict = {}
                        stats.oid_counter_dict = {}

                        # provide a value that can tested for
                        sws.sw_storm_counter_dict["abc"] = "def"
                        self.assertTrue("abc" in sws.sw_storm_counter_dict)

                        self.assertTrue(sw.sw_clear_dicts())
                        self.assertFalse("abc" in sws.sw_storm_counter_dict)

                        # now make sure we get an exception
                        sws.sw_config_category = 3
                        self.assertFalse(sw.sw_clear_dicts())


    def test_sw_load_trap_config(self):
        """ Test sw_load_trap_config(_config) """
        trap_dict_info = {
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
            "trap_config": { },
            "notify OID len": 10,
        }

        # normal operation, and variations
        ret1 = sw.sw_load_trap_config(trap_dict_info)
        self.assertEqual(ret1, 0)
        self.assertIsInstance(ret1, int)

        trap_dict_info["trap_config"]["notify_oids"] = [
            { "oidx": "1.3.6.1.4.1.9999.9.9.888" }
        ]
        ret2 = sw.sw_load_trap_config(trap_dict_info)
        self.assertEqual(ret2, 0)
        self.assertIsInstance(ret2, int)

        trap_dict_info["trap_config"]["metric_log_notification_threshold_pct"] = 33
        ret3 = sw.sw_load_trap_config(trap_dict_info)
        self.assertEqual(ret3, 0)
        self.assertIsInstance(ret3, int)

        trap_dict_info["trap_config"]["sw_interval_in_seconds"] = 50
        ret4 = sw.sw_load_trap_config(trap_dict_info)
        self.assertEqual(ret4, 0)
        self.assertIsInstance(ret4, int)

        trap_dict_info["trap_config"]["notify_oids"] = [
            {
                "oid": "1.3.6.1.4.1.9999.9.9.888",
                "sw_high_water_in_interval": 3,
                "sw_low_water_in_interval": 2,
                "category": "abc",
            }
        ]
        ret5 = sw.sw_load_trap_config(trap_dict_info)
        self.assertEqual(ret5, 1)
        self.assertIsInstance(ret5, int)

        delattr(sws, 'sw_storm_active_dict')
        ret6 = sw.sw_load_trap_config(trap_dict_info)
        self.assertEqual(ret6, 1)
        self.assertIsInstance(ret6, int)


    def test_sw_log_metrics(self):
        """
        Test sw_clear_log_metrics
        """
        stats.total_notifications = 3
        stats.total_notifications = 50
        sws.sw_interval_in_seconds = 30
        stats.agent_counter_dict = {"a": 3, "b": 40}
        stats.metric_log_notification_threshold_pct = 30

        with patch('trapd_stormwatch.ecomp_logger') as magic_ecomp_logger:
            sw.sw_log_metrics()
            self.assertEqual(magic_ecomp_logger.call_count, 3)


    def test_increment_existing_counter(self):
        """
        Test increment counter. There should NOT be an exception.
        """
        oid = ".1.2.3.4.5.6"
        sws.sw_config_oid_dict[oid] = True
        sws.sw_config_low_water_in_interval_dict[oid] = 1
        sws.sw_config_high_water_in_interval_dict[oid] = 10

        loc_agent = "192.168.1.1"
        stats.agent_counter_dict[loc_agent] = 2
        stats.oid_counter_dict[oid] = 102

        sv_total_notifications = stats.total_notifications
        sv_agent_count_dict = stats.agent_counter_dict[loc_agent]
        sv_oid_count_dict = stats.oid_counter_dict[oid]
        try:
            sw.stats_increment_counters(loc_agent, oid)
            result = True
        except Exception as e:
            result = False
        self.assertEqual(result, True, "test_increment_existing_counter")
        self.assertEqual(stats.total_notifications, sv_total_notifications+1)
        self.assertEqual(stats.agent_counter_dict[loc_agent], sv_agent_count_dict+1)
        self.assertEqual(stats.oid_counter_dict[oid], sv_oid_count_dict+1)

        # try again, without agent_counter_dict[loc_agent]
        del stats.agent_counter_dict[loc_agent]
        try:
            sw.stats_increment_counters(loc_agent, oid)
            result = True
        except Exception as e:
            result = False
        self.assertEqual(result, True, "test_increment_existing_counter")
        self.assertEqual(stats.total_notifications, sv_total_notifications+2)
        self.assertEqual(stats.agent_counter_dict[loc_agent], 1)
        self.assertEqual(stats.oid_counter_dict[oid], sv_oid_count_dict+2)

        # try again, but with stats.total_notifications removed
        delattr(stats, "total_notifications")

        try:
            sw.stats_increment_counters(loc_agent, oid)
            result = True
        except:
            result = False

        self.assertEqual(result, True, "stats.total_notifications removed")
        self.assertEqual(stats.total_notifications, 1)
        self.assertEqual(stats.agent_counter_dict[loc_agent], 2)
        self.assertEqual(stats.oid_counter_dict[oid], sv_oid_count_dict+3)


    def test_sw_storm_active(self):
        """
        Test sw_storm_active()
        """
        print(f"sw_last_stormwatch_dict_analysis={sws.sw_last_stormwatch_dict_analysis}")

        # initialize attributes not handled by sw_init()
        stats.oid_counter_dict = {}

        # initialize attributes for the test
        loc_agent = "192.168.1.1"
        loc_oid = ".1.2.3.4.5.6"
        sws.sw_config_high_water_in_interval_dict[loc_oid] = 50
        sws.sw_storm_counter_dict = {}
        dict_key = loc_agent + " " + loc_oid

        # Four cases to test.

        # #1
        # if sws.sw_storm_active_dict[dict_key] exists
        #    return True
        # #2
        # else (sws.sw_storm_active_dict does not exist)
        #    if sws.sw_storm_counter_dict[dict_key] > sws.sw_config_high_water_in_interval_dict[loc_oid]
        #        create sws.sw_storm_active_dict[dict_key]
        #        return True
        # #3
        #    else
        #        return False
        # #4
        # sws.sw_last_stormwatch_dict_analysis gets reset often.
        # but if time.time() - sw_last_stormwatch_dict_analysis > than sw_interval_in_seconds,
        # then sw_reset_counter_dict() is invoked.

        # start with sws.sw_storm_active_dict[dict_key] does not exist
        # and sws.sw_storm_counter_dict[dict_key] < high_water_mark
        sws.sw_storm_active_dict = {}
        sws.sw_storm_counter_dict[dict_key] = 10
        # Should return False
        self.assertFalse(sw.sw_storm_active(loc_agent, loc_oid))
        # self.assertFalse(hasattr(sws, "sw_storm_active_dict"))

        # now with sws.sw_storm_counter_dict[dict_key] > high_water_mark
        sws.sw_storm_counter_dict[dict_key] = 60
        # should create sws.sw_storm_active_dict[dict_key] and return True
        self.assertTrue(sw.sw_storm_active(loc_agent, loc_oid))
        self.assertTrue(sws.sw_storm_active_dict.get(dict_key) != None)

        # now that sws.sw_storm_active_dict[dict_key] exists
        # should return True
        self.assertTrue(sw.sw_storm_active(loc_agent, loc_oid))

        # now force sws.sw_last_stormwatch_dict_analysis to an old value
        sws.sw_last_stormwatch_dict_analysis = (
            int(time.time()) - sws.sw_interval_in_seconds - 20
        )
        # and make certain that stats.oid_counter_dict got cleared.
        if not hasattr(stats, "oid_counter_dict"):
            stats.oid_counter_dict = {}
        stats.oid_counter_dict["abc"] = 5
        self.assertTrue(sw.sw_storm_active(loc_agent, loc_oid))
        self.assertTrue(not hasattr(sws, "oid_counter_dict"))
        # .get("abc") != None)


    @patch('trapd_stormwatch.ecomp_logger')
    def test_sw_reset_counter_dict(self, magic_ecomp_logger):
        """ test sw_reset_counter_dict() """

        loc_agent = "192.168.1.1"
        loc_oid = ".1.2.3.4.5.6"
        loc_agent_oid = loc_agent + " " + loc_oid

        self.assertTrue(sw.sw_reset_counter_dict())
        self.assertEqual(magic_ecomp_logger.call_count, 2)

        # cases:
        # for lao in storm_active_dict:
        #     storm_counter_dict[lao] >= high_water_val[lo]
        #     storm_counter_dict[lao] < high_water_val[lo]
        #         storm_counter_dict[lao] < low_water_val[lo]
        #         storm_counter_dict[lao] >= low_water_val[lo]

        with patch.dict(sws.sw_storm_counter_dict, {
                loc_agent_oid: 20
        }):
            # values around the 20 above
            for high_water_mark in [2, 60]:
                # values around the 20 above
                for low_water_mark in [0, 30]:
                    with patch.dict(sws.sw_config_high_water_in_interval_dict, {
                            loc_oid: high_water_mark
                    }):
                        with patch.dict(sws.sw_config_low_water_in_interval_dict, {
                                loc_oid: low_water_mark
                        }):
                            with patch.dict(sws.sw_storm_active_dict, {
                                    loc_agent_oid: "anything"
                            }):
                                sv_storm_counter = sws.sw_storm_counter_dict[loc_agent_oid]
                                magic_ecomp_logger.call_count = 0
                                self.assertTrue(sw.sw_reset_counter_dict())
                                self.assertEqual(magic_ecomp_logger.call_count, 3)
                                self.assertEqual(sws.sw_storm_counter_dict[loc_agent_oid], 0)


if __name__ == "__main__": # pragma: no cover
    # sws.init()
    unittest.main()
