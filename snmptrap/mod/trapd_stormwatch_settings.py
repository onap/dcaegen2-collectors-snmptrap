# ============LICENSE_START=======================================================
# Copyright (c) 2020-2021 AT&T Intellectual Property. All rights reserved.
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
"""
"""

__docformat__ = "restructuredtext"


def init():

    # <Storm Watch>
    #
    #     sw_storm_counter_dict
    #        key [<ip address>.<notify oid>] -> count
    #
    #     sw_storm_active_dict
    #        key [<ip address>.<notify oid>] -> True (or False, but no key present
    #                                           means False)
    #
    #     sw_config_oid_dict
    #        key [<notify oid>] -> "true" (key presence means it participates)
    #
    #     sw_config_low_water_in_interval_dict
    #        key [<notify oid>] -> <int> value that stormActive turns False
    #
    #     sw_config_high_water_in_interval_dict
    #        key [<notify oid>] -> <int> value that stormActive turns True
    #
    global sw_storm_counter_dict
    sw_storm_counter_dict = {}

    global sw_storm_active_dict
    sw_storm_active_dict = {}

    global sw_config_oid_dict
    sw_config_oid_dict = {}
    global sw_config_low_water_in_interval_dict
    sw_config_low_water_in_interval_dict = {}
    global sw_config_high_water_in_interval_dict
    sw_config_high_water_in_interval_dict = {}
    global sw_config_category
    sw_config_category = {}

    global sw_interval_in_seconds
    sw_interval_in_seconds = 60
    global sw_last_stormwatch_dict_analysis
    sw_last_stormwatch_dict_analysis = 0
    # </Storm Watch>
