import pytest
import unittest
import trapd_exit

pid_file="/tmp/test_pid_file"
pid_file_dne="/tmp/test_pid_file_NOT"

import trapd_stormwatch_settings as sws 

class test_cleanup_and_exit(unittest.TestCase):
    """
    Test for presense of required vars
    """
 

    def test_nonexistent_dict(self):
        """
        Test nosuch var
        """
        sws.init()
        try:
            sws.no_such_var
            result = True
        except:
            result = False

        self.assertEqual(result, False)
 
    def test_storm_counter_dict(self):
        """
        Test storm_counter_dict
        """
        sws.init()
        try:
            sws.sw_storm_counter_dict
            result = True
        except:
            result = False

        self.assertEqual(result, True)
 
    def test_storm_active_dict(self):
        """
        Test storm_active_dict
        """

        sws.init()
        try:
            sws.sw_storm_active_dict
            result = True
        except:
            result = False

        self.assertEqual(result, True)

    def test_sw_config_oid_dict(self):
        """
        Test sw_config_oid_dict
        """

        sws.init()
        try:
            sws.sw_config_oid_dict
            result = True
        except:
            result = False

        self.assertEqual(result, True)

    def test_sw_config_low_water_in_interval_dict(self):
        """
        Test low_water
        """

        sws.init()
        try:
            sws.sw_config_low_water_in_interval_dict
            result = True
        except:
            result = False

        self.assertEqual(result, True)

    def test_sw_config_high_water_in_interval_dict(self):
        """
        Test high water dict
        """

        sws.init()
        try:
            sws.sw_config_high_water_in_interval_dict
            result = True
        except:
            result = False

        self.assertEqual(result, True)

    def test_sw_config_category(self):
        """
        Test category
        """

        sws.init()
        try:
            sws.sw_config_category
            result = True
        except:
            result = False

        self.assertEqual(result, True)

    def test_sw_interval_in_seconds(self):
        """
        Test sw_interval
        """

        sws.init()
        try:
            str(sws.sw_interval_in_seconds).isnumeric()
            result = True
        except:
            result = False

        self.assertEqual(result, True)

    def test_sw_last_stormwatch_dict_analysis(self):
        """
        Test last_stormwatch_dict_analysis
        """

        sws.init()
        try:
            str(sws.sw_last_stormwatch_dict_analysis).isnumeric()
            result = True
        except:
            result = False

        self.assertEqual(result, True)

if __name__ == '__main__':
    # sws.init()
    unittest.main()
