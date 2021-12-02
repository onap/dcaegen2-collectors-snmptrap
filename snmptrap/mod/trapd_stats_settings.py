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

    # <stats>
    #
    #     oid_counter_dict
    #        key [<notify oid>] -> count
    #
    #     agent_counter_dict
    #        key [<agent>] -> count
    #
    global oid_counter_dict
    oid_counter_dict = {}

    global agent_counter_dict
    agent_counter_dict = {}

    global total_notifications
    total_notifications = 0

    global metric_log_notification_threshold_pct
    metric_log_notification_threshold_pct = 25

    # </stats>
