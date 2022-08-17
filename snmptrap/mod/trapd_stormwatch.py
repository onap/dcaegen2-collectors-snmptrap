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
"""
trapd_stormwatch makes the decision on whether an
arriving SNMP trap is exceeding a pre-configured
threshold (storm), and if so it will return "False"
so the trap can be logged and immediately discarded
"""

__docformat__ = "restructuredtext"

import sys
import os
import string
import time

from trapd_io import stdout_logger, ecomp_logger
import trapd_settings as tds
import trapd_stats_settings as stats
import trapd_stormwatch_settings as sws
from trapd_exit import cleanup_and_exit

prog_name = os.path.basename(__file__)


def sw_init():

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
    sws.sw_counter_dict = {}
    sws.sw_storm_active_dict = {}
    sws.sw_config_oid_dict = {}
    sws.sw_config_low_water_in_interval_dict = {}
    sws.sw_config_high_water_in_interval_dict = {}
    sws.sw_interval_in_seconds = 60


# # # # # # # # # # # # #
# fx: sw_clear_dicts
#      - clear out all dictionaries in stats
#      - returns True if yes, False if no
# # # # # # # # # # # # #
def sw_clear_dicts():
    """
    Clear all storm watch dictionaries
    :Parameters:
    :Exceptions:
      none
    :Keywords:
      stormwatch count threshold
    :Variables:
    """
    try:
        if hasattr(stats, "oid_counter_dict"):
            stats.oid_counter_dict.clear()
        if hasattr(stats, "agent_counter_dict"):
            stats.agent_counter_dict.clear()
        if hasattr(sws, "sw_storm_active_dict"):
            sws.sw_storm_active_dict.clear()
        if hasattr(sws, "sw_storm_counter_dict"):
            sws.sw_storm_counter_dict.clear()
        if hasattr(sws, "sw_config_oid_dict"):
            sws.sw_config_oid_dict.clear()
        if hasattr(sws, "sw_config_low_water_in_interval_dict"):
            sws.sw_config_low_water_in_interval_dict.clear()
        if hasattr(sws, "sw_config_high_water_in_interval_dict"):
            sws.sw_config_high_water_in_interval_dict.clear()
        if hasattr(sws, "sw_config_category"):
            sws.sw_config_category.clear()
        return True

    except Exception as e:
        print(f">>>> got exception {e}")
        msg = "unable to reset stormwatch dictionaries - results will be indeterminate: %s" % (e)
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)
        return False


# # # # # # # # # # # # #
# fx: sw_load_trap_config
#      - load trap configurations from CBS response
# # # # # # # # # # # # #


def sw_load_trap_config(_config):
    """
    Load trap configs into dictionary
    :Parameters:
      _config: trapd_config from CBS
    :Exceptions:
    """

    # clear any dicts present from previous invocations
    try:
        sws.sw_storm_active_dict
        ret = sw_clear_dicts()
        msg = "reset existing sws dictionaries to empty"
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    except (NameError, AttributeError):
        msg = "sws dictionaries not present - initializing"
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        ret = sw_init()

    # set last storm analysis to now
    sws.sw_last_stormwatch_dict_analysis = int(time.time())

    # get metric % threshold for logging trap count by-agent to metric log
    try:
        stats.metric_log_notification_threshold_pct = int(
            _config["trap_config"]["metric_log_notification_threshold_pct"]
        )
        msg = "metric_log_notification_threshold_pct value: %d" % stats.metric_log_notification_threshold_pct
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    except Exception as e:
        msg = "metric_log_notification_threshold_pct not present in config - default to 25"
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_WARN, tds.CODE_GENERAL, msg)
        stats.metric_log_notification_threshold_pct = 25

    # get stormwatch interval; default to 60 seconds
    try:
        sws.sw_interval_in_seconds = int(_config["trap_config"]["sw_interval_in_seconds"])
        msg = "sw_interval_in_seconds value: %d" % sws.sw_interval_in_seconds
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    except Exception as e:
        msg = "sw_interval_in_seconds not present in config - default to 60 seconds"
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_WARN, tds.CODE_GENERAL, msg)
        sws.sw_interval_in_seconds = 60

    # add trap configs from CBS json structure to running config
    try:
        notify_oids = _config["trap_config"]["notify_oids"]

    except Exception as e:
        msg = "no trap_config or notify_oids defined"
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_WARN, tds.CODE_GENERAL, msg)
        return 0

    trap_block_counter = 0
    for trap_block in notify_oids:
        # oid
        try:
            _oid = trap_block["oid"]

        except Exception as e:
            msg = "missing oid value in notify_oids - oid section of CBS config - using empty value, disregard entry"
            ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_WARN, tds.CODE_GENERAL, msg)
            _oid = None

        # sw_high_water_in_interval
        try:
            _sw_high_water_in_interval = int(trap_block["sw_high_water_in_interval"])

        except Exception as e:
            msg = (
                "missing sw_high_water_in_interval value in notify_oids - oid section of CBS config - using empty value"
            )
            ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_WARN, tds.CODE_GENERAL, msg)
            _sw_high_water_in_interval = None

        # sw_low_water_in_interval
        try:
            _sw_low_water_in_interval = int(trap_block["sw_low_water_in_interval"])

        except Exception as e:
            msg = (
                "missing sw_low_water_in_interval value in notify_oids - oid section of CBS config - using empty value"
            )
            ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_WARN, tds.CODE_GENERAL, msg)
            _sw_low_water_in_interval = None

        # category
        try:
            _category = trap_block["category"]

        except Exception as e:
            msg = "missing category value in notify_oids - oid section of CBS config - using empty value"
            ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_WARN, tds.CODE_GENERAL, msg)
            _category = None

        if (
            _oid is not None
            and _category is not None
            and _sw_low_water_in_interval is not None
            and _sw_high_water_in_interval is not None
            and _sw_low_water_in_interval < _sw_high_water_in_interval
        ):
            # FMDL:  Do we actually need sw_config_oid_dict?
            msg = "oid: %s sw_high_water_in_interval: %d sw_low_water_in_interval: %d category: %s" % (
                _oid,
                _sw_high_water_in_interval,
                _sw_low_water_in_interval,
                _category,
            )
            ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
            sws.sw_config_oid_dict[_oid] = True
            sws.sw_config_low_water_in_interval_dict[_oid] = _sw_low_water_in_interval
            sws.sw_config_high_water_in_interval_dict[_oid] = _sw_high_water_in_interval
            sws.sw_config_category[_oid] = _category
            trap_block_counter += 1
        else:
            msg = "Missing or incorrect value for stormwatch config entry %d: skipping: %s" % (
                trap_block_counter,
                trap_block,
            )
            ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    return trap_block_counter


# # # # # # # # # # # # #
# fx: sw_log_metrics
#      - log stats for any count in interval that is > sw_metric_log_notification_threshold_pct % of total arriving traps
# # # # # # # # # # # # #
def sw_log_metrics():
    """
    Log counts for agents that exceed sw_metric_log_notification_threshold_pct % of
    total traps that arrived in interval
    :Parameters:
    :Exceptions:
      none
    :Keywords:
      stormwatch metrics
    :Variables:
    """

    msg = "total notifications: %d, interval in seconds: %d" % (stats.total_notifications, sws.sw_interval_in_seconds)
    ecomp_logger(tds.LOG_TYPE_METRICS, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    # print metrics for total traps and traps-per-second avg
    # during sample interval
    avg_traps_per_second = stats.total_notifications / 60
    msg = "total traps: %d, interval in seconds: %d, average traps-per-second: %d" % (
        stats.total_notifications,
        sws.sw_interval_in_seconds,
        avg_traps_per_second,
    )
    ecomp_logger(tds.LOG_TYPE_METRICS, tds.SEV_WARN, tds.CODE_GENERAL, msg)

    # print metrics for any agent that represents more than stats.metric_log_notification_threshold_pct
    # during sample interval
    for k in stats.agent_counter_dict:
        c = stats.agent_counter_dict[k]
        p = c / stats.total_notifications * 100
        if p > stats.metric_log_notification_threshold_pct:
            msg = "agent: %s, notifications: %d, interval in seconds: %d, percent of total traps: %d" % (
                k,
                c,
                sws.sw_interval_in_seconds,
                p,
            )
            ecomp_logger(tds.LOG_TYPE_METRICS, tds.SEV_WARN, tds.CODE_GENERAL, msg)


# # # # # # # # # # # # #
# fx: stats_increment_counters
#      - increment dictionary counters that are accumulating
#      - total traps by OID and agent for each sample interval
# # # # # # # # # # # # #


def stats_increment_counters(_loc_agent, _loc_oid):
    """
    update counters tracking traps-per-interval by
    OID and agent
    :Parameters:
      _loc_agent
        agent address from trap PDU
      _loc_oid
        notify OID from trap PDU
    :Exceptions:
      none
    :Keywords:
      stormwatch stats metrics
    :Variables:
    """
    # increment oid occurances in window
    msg = "increment metric counters for %s %s" % (_loc_agent, _loc_oid)
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
    try:
        stats.total_notifications += 1
    except Exception as e:
        stats.total_notifications = 1

    try:
        stats.oid_counter_dict[_loc_oid] += 1
    except Exception as e:
        stats.oid_counter_dict[_loc_oid] = 1

    # increment agent occurances in window
    try:
        stats.agent_counter_dict[_loc_agent] += 1
    except Exception as e:
        stats.agent_counter_dict[_loc_agent] = 1


# # # # # # # # # # # # #
# fx: sw_storm_active
#      - check if storm is active for agent/oid
#      - returns True if yes, False if no
# # # # # # # # # # # # #
def sw_storm_active(_loc_agent, _loc_oid):
    """
    Check if this event is currently in an
    active storm state.
    :Parameters:
      _loc_agent
        agent address from trap PDU
      _loc_oid
        notify OID from trap PDU
    :Exceptions:
      none
    :Keywords:
      stormwatch count threshold
    :Variables:
    """

    # we have to come here for every arriving trap, so increment
    # trap counter dictionaries while we are here
    stats_increment_counters(_loc_agent, _loc_oid)

    # if we are at or above stormwatch interval, re-eval and re-set
    elapsed_time = int(time.time()) - sws.sw_last_stormwatch_dict_analysis
    if elapsed_time >= sws.sw_interval_in_seconds:
        msg = (
            "%d seconds has elapsed since stormwatch dictionary eval (%d second threshold) - check and reset counters "
            % (elapsed_time, sws.sw_interval_in_seconds)
        )
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        sw_log_metrics()
        sw_reset_counter_dict()

    # Note:  If there's a sw_config_high_water_in_interval config value present
    # that means it's participating in stormwatch, otherwise bail out
    try:
        _high_water_val = sws.sw_config_high_water_in_interval_dict[_loc_oid]
        msg = "%s present in stormwatch config - high water value: %d" % (_loc_oid, _high_water_val)
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
    except Exception as e:
        return False

    # build stormwatch dict key by appending agent IP and trap oid
    _dict_key = _loc_agent + " " + _loc_oid

    # increment traps encountered for agent/oid
    sw_increment_counter(_dict_key)

    # first check if storm is active for _dict_key (early bail-out if so)
    msg = "check if stormWatch is active for %s" % (_dict_key)
    ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
    if sws.sw_storm_active_dict.get(_dict_key) is not None:
        msg = "stormWatch is active for %s - return true" % (_dict_key)
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        return True
    else:
        msg = "no stormWatch active entry for %s - continue" % (_dict_key)
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)

    # if we got this far, trap is in stormwatch configs, we've incremented
    # counter in sw_storm_counter_dict - figure out if we are over limit
    if sws.sw_storm_counter_dict[_dict_key] > _high_water_val:
        print(
            f"sws.sw_storm_counter_dict[{_dict_key}]({sws.sw_storm_counter_dict[_dict_key]}) > _high_water_val ({_high_water_val})"
        )

        _loc_agent = _dict_key.split()[0]
        _loc_oid = _dict_key.split()[1]
        msg = "STORM ACTIVE: received %d events (%s) from %s (greater than high water threshold: %d)" % (
            sws.sw_storm_counter_dict[_dict_key],
            _loc_oid,
            _loc_agent,
            _high_water_val,
        )
        ecomp_logger(tds.LOG_TYPE_AUDIT, tds.SEV_WARN, tds.CODE_GENERAL, msg)
        try:
            sws.sw_storm_active_dict[_dict_key] = True
        except Exception as e:
            msg = "ERROR setting %s in storm active state: %s " % (_dict_key, e)
            ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_ERROR, tds.CODE_GENERAL, msg)
        return True
    else:
        print(
            f"NOT sws.sw_storm_counter_dict[{_dict_key}]({sws.sw_storm_counter_dict[_dict_key]}) > _high_water_val ({_high_water_val})"
        )
        return False


# # # # # # # # # # # # #
# fx: sw_reset_counter_dict
#      - reset counter dictionary on <interval> boundaries
# # # # # # # # # # # # #


def sw_reset_counter_dict():
    """
    Create new storm_active_dict based on quantities received during
    last sample interval
    :Parameters:
    :Exceptions:
      none
    :Keywords:
      stormwatch count threshold
    :Variables:
    """

    # <stats>
    # publish stats to MR...
    try:
        msg = "publish counts-by-oid from stats.oid_counter_dict"
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        msg = "publish count-by-agent from stats.agent_counter_dict"
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
    except Exception as e:
        msg = "unable to publish counts by oid and agent to MR: " % (e)
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)

    # ...and now reset stats counters to start next interval
    try:
        stats.oid_counter_dict.clear()
        stats.agent_counter_dict.clear()
        stats.total_notifications = 0
    except Exception as e:
        msg = "unable to reset counts by oid and agent dictionaries - stats will be INNACURATE: " % (e)
        ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_WARN, tds.CODE_GENERAL, msg)
    # </stats>

    # <storm watch active>

    # for k in sws.sw_storm_active_dict:
    #   File "./snmptrapd.py", line 642, in notif_receiver_cb
    #     if stormwatch.sw_storm_active(tds.trap_dict["agent address"], tds.trap_dict["notify OID"]):
    #   File "/opt/app/snmptrap/bin/mod/trapd_stormwatch.py", line 299, in sw_storm_active
    #     sw_reset_counter_dict()
    #   File "/opt/app/snmptrap/bin/mod/trapd_stormwatch.py", line 381, in sw_reset_counter_dict
    #     for k in sws.sw_storm_active_dict:
    # RuntimeError: dictionary changed size during iteration
    # FIXME:  changed to "for k in list(sw_storm_active_dict)" as explained here:
    # see https://stackoverflow.com/questions/20418851/delete-an-entry-from-a-dictionary-python

    for k in list(sws.sw_storm_active_dict):
        _loc_agent = k.split()[0]
        _loc_oid = k.split()[1]

        _high_water_val = sws.sw_config_high_water_in_interval_dict[_loc_oid]

        if sws.sw_storm_counter_dict[k] >= _high_water_val:
            msg = "%s remaining in storm state, received %d events (GE to upper threshold: %d)" % (
                k,
                sws.sw_storm_counter_dict[k],
                _high_water_val,
            )
            ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
            sws.sw_storm_counter_dict[k] = 0
        else:
            _low_water_val = sws.sw_config_low_water_in_interval_dict[_loc_oid]
            if sws.sw_storm_counter_dict[k] < _low_water_val:
                try:
                    msg = "STORM OVER: received %d events (%s) from %s (less than low water threshold: %d)" % (
                        sws.sw_storm_counter_dict[k],
                        _loc_oid,
                        _loc_agent,
                        _low_water_val,
                    )
                    ecomp_logger(tds.LOG_TYPE_AUDIT, tds.SEV_WARN, tds.CODE_GENERAL, msg)
                    del sws.sw_storm_active_dict[k]
                    sws.sw_storm_counter_dict[k] = 0
                except Exception as e:
                    msg = (
                        "unable to remove %s from storm active dictionary - TRAPS MAY BE DISCARDED UNINTENTIONALLY!  Reason:  %s "
                        % (k, e)
                    )
                    ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_ERROR, tds.CODE_GENERAL, msg)
            else:
                msg = "%s remaining in storm state, received %d events (GE to lower threshold: %d)" % (
                    k,
                    sws.sw_storm_counter_dict[k],
                    _low_water_val,
                )
                ecomp_logger(tds.LOG_TYPE_ERROR, tds.SEV_INFO, tds.CODE_GENERAL, msg)
                sws.sw_storm_counter_dict[k] = 0

    sws.sw_last_stormwatch_dict_analysis = int(time.time())

    return True


# # # # # # # # # # # # #
# fx: sw_increment_counter
#      - increment OID and agent trap counters
#        based on arriving trap attributes
# # # # # # # # # # # # #


def sw_increment_counter(_dict_key):
    """
    Add to appropriate counter based on arriving trap
    agent and OID
    :Parameters:
      _dict_key
        agent address from trap PDU and notify OID
        trap PDU, separated by a space
    :Exceptions:
      none
    :Keywords:
      stormwatch count threshold
    :Variables:
    """

    try:
        sws.sw_storm_counter_dict[_dict_key] += 1
        msg = "stormwatch counter for %s now: %d" % (_dict_key, sws.sw_storm_counter_dict[_dict_key])
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        return True
    except Exception as E:
        msg = "first trap for %s - init stormwatch counter to 1" % (_dict_key)
        ecomp_logger(tds.LOG_TYPE_DEBUG, tds.SEV_INFO, tds.CODE_GENERAL, msg)
        sws.sw_storm_counter_dict[_dict_key] = 1
        return True
