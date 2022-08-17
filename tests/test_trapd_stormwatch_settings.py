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

pid_file = "/tmp/test_pid_file"
pid_file_dne = "/tmp/test_pid_file_NOT"

import trapd_stormwatch_settings as sws


# @unittest.skip("DONE")
class test_cleanup_and_exit(unittest.TestCase):
    """
    Test for presense of required vars
    """

    def test_nonexistent_dict(self):
        """
        Test nosuch var
        """
        sws.init()
        self.assertFalse(hasattr(sws, 'no_such_var'))


    def test_storm_counter_dict(self):
        """
        Test storm_counter_dict
        """
        sws.init()
        self.assertTrue(hasattr(sws, 'sw_storm_counter_dict'))


    def test_storm_active_dict(self):
        """
        Test storm_active_dict
        """

        sws.init()
        self.assertTrue(hasattr(sws, 'sw_storm_active_dict'))


    def test_sw_config_oid_dict(self):
        """
        Test sw_config_oid_dict
        """

        sws.init()
        self.assertTrue(hasattr(sws, 'sw_config_oid_dict'))


    def test_sw_config_low_water_in_interval_dict(self):
        """
        Test low_water
        """

        sws.init()
        self.assertTrue(hasattr(sws, 'sw_config_low_water_in_interval_dict'))


    def test_sw_config_high_water_in_interval_dict(self):
        """
        Test high water dict
        """

        sws.init()
        self.assertTrue(hasattr(sws, 'sw_config_high_water_in_interval_dict'))


    def test_sw_config_category(self):
        """
        Test category
        """

        sws.init()
        self.assertTrue(hasattr(sws, 'sw_config_category'))


    def test_sw_interval_in_seconds(self):
        """
        Test sw_interval
        """
        sws.init()
        self.assertTrue(hasattr(sws, 'sw_interval_in_seconds'))
        self.assertTrue(str(sws.sw_interval_in_seconds).isnumeric())


    def test_sw_last_stormwatch_dict_analysis(self):
        """
        Test last_stormwatch_dict_analysis
        """
        sws.init()
        self.assertTrue(hasattr(sws, 'sw_last_stormwatch_dict_analysis'))
        self.assertTrue(str(sws.sw_last_stormwatch_dict_analysis).isnumeric())


if __name__ == "__main__": # pragma: no cover
    unittest.main(verbosity=2)
