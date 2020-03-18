# ============LICENSE_START=======================================================
# Copyright (c) 2020 AT&T Intellectual Property. All rights reserved.
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
import unittest
import trapd_exit
import time

import trapd_stormwatch as sw 
import trapd_stormwatch_settings as sws 
import trapd_stats_settings as stats

class test_cleanup_and_exit(unittest.TestCase):
    """
    Test for presense of required vars
    """
 

    def test_increment_existing_counter(self):
        """
        Test increment counter
        """
        sw.sw_init()
        stats.init()

        oid=".1.2.3.4.5.6"
        sws.sw_config_oid_dict[oid] = True
        sws.sw_config_low_water_in_interval_dict[oid] = 1
        sws.sw_config_high_water_in_interval_dict[oid] = 10

        try:
            sw.stats_increment_counters("192.168.1.1", ".1.2.3.4.5.6")
            result = True
        except:
            result = False

        self.assertEqual(result, True)

        # try again, but with stats.total_notifications removed
        delattr(stats, "total_notifications")

        try:
            sw.stats_increment_counters("192.168.1.1", ".1.2.3.4.5.6")
            result = True
        except:
            result = False

        self.assertEqual(result, True)

    def test_sw_clear_dicts(self):
        """
        Test sw_clear_dicts
        """
        sw.sw_init()
        # initialize attributes not handled by sw_init()
        sws.sw_storm_counter_dict = {}
        stats.agent_counter_dict = {}
        stats.oid_counter_dict = {}
        sws.sw_config_category = {}
        # provide a value that can tested for
        sws.sw_storm_counter_dict["abc"] = "def"

        sw.sw_clear_dicts()
        self.assertFalse("abc" in sws.sw_storm_counter_dict)

        # now make sure we get an exception
        sws.sw_config_category = 3
        self.assertFalse(sw.sw_clear_dicts())
        
        # clean up the attributes we added above
        delattr(sws, "sw_storm_counter_dict")
        delattr(stats, "agent_counter_dict")
        delattr(stats, "oid_counter_dict")
        delattr(sws, "sw_config_category")

    def test_sw_log_metrics(self):
        """
        Test sw_clear_log_metrics
        """
        sw.sw_init()

        stats.total_notifications = 3
        stats.total_notifications = 50
        sws.sw_interval_in_seconds = 30
        stats.agent_counter_dict = { "a": 3, "b": 40 }
        stats.metric_log_notification_threshold_pct = 30
        sw.sw_log_metrics()

        # make sure we got this far
        assert(True)

    def test_sw_storm_active(self):
        """
        Test sw_storm_active()
        """
        sw.sw_init()
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
        sws.sw_last_stormwatch_dict_analysis = int(time.time()) - sws.sw_interval_in_seconds - 20
        # and make certain that stats.oid_counter_dict got cleared.
        if not hasattr(stats, "oid_counter_dict"):
            stats.oid_counter_dict = {}
        stats.oid_counter_dict["abc"] = 5
        self.assertTrue(sw.sw_storm_active(loc_agent, loc_oid))
        self.assertTrue(not hasattr(sws,"oid_counter_dict"))
        # .get("abc") != None)

if __name__ == '__main__':
    # sws.init()
    unittest.main()
