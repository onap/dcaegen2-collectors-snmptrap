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


if __name__ == '__main__':
    # sws.init()
    unittest.main()
