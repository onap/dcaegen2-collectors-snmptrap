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
