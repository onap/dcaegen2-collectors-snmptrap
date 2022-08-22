#!/usr/bin/env bash
# ============LICENSE_START=======================================================
# Copyright (c) 2017-2022 AT&T Intellectual Property. All rights reserved.
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
#
#

script_name=`basename "$0"`

# sleep_time=.1		# in seconds
sleep_time=1		# in seconds

log_fd=/var/tmp/${script_name}.log
log_lines=0
max_log_lines=4000

num_days_to_keep_logs=7

# find the best tool for the job
if [ `command -v pypy3` ]
then
   PY_BINARY=pypy3
else
   if [ `command -v python3` ]
   then
      PY_BINARY=python3
   else
      if [ `command -v python` ]
      then
         PY_BINARY=python
      else
         echo "ERROR: no pypy3 or python available in container - FATAL ERROR, exiting"
         exit 1
      fi
   fi
fi

# logging utility
logFx()
{
_fx=$1
# skipping verbosity setting
_verbosity=$2
_log_message=$3

   echo "`date` `date +%s` ${_fx} ${_error_code} ${_log_message}" >> ${log_fd}

   # log_lines=`wc -l ${log_fd} | awk {'print $1'} | bc`
   # log_lines=$((${log_lines}+1))

   # if [ ${log_lines} -ge ${max_log_lines} ]
   # then
   #    if [ -f ${log_fd} ]
   #    then
   #       mv -f ${log_fd} ${log_fd}.old
   #    fi
   # fi
}

run_10sec_jobs()
{
    # send heartbeat
    ${PY_BINARY} /opt/app/snmptrap/bin/send_hb_trap localhost 6162 > /var/tmp/send_hb_trap.out 2>&1 &
    rc=$?
    logFx ${FUNCNAME[0]} 0 "send_hb_trap returned ${rc}"

    # other 10 second jobs below here

    return ${rc}
}

run_minute_jobs()
{
rc=0
    # add other minute jobs below here

    return ${rc}
}

run_hourly_jobs()
{
    # no hourly jobs scheduled at this time
    rc=0

    # add other hourly jobs below here

    return ${rc}
}

run_daily_jobs()
{
    rc=0

    # remove old logs
    for f in `find /opt/app/snmptrap/logs -type f -mtime +${num_days_to_keep_logs}`
    do
       logFx ${FUNCNAME[0]} 0 "removing $f"
       rm $f
    done

    # move scheduler log_fd to daily backup
    mv -f ${log_fd} ${log_fd}.`date +%a`

    # add other daily jobs below here

    return ${rc}
}


# # # # # # # # # # # # # #
# main HCCCKK area
# # # # # # # # # # # # # #

begin_minute=`date +%M | bc`

# wait for minute to roll to new one
logFx ${FUNCNAME[0]} 0 "waiting for new minute..."
while [ ${begin_minute} -eq `date +%M | bc` ]
do
   sleep .1
done

SECONDS=0
logFx ${FUNCNAME[0]} 0 "scheduler synced to new minute"
last_minute=`date +%M`
last_hour=`date +%H`
last_day=`date +%j`

logFx ${FUNCNAME[0]} 0 "entering endless loop"
while(true)
do
   if [ $SECONDS -ge 10 ]
   then
      # run every 10 seconds jobs
      logFx ${FUNCNAME[0]} 0 "$SECONDS seconds have elapsed - calling run_10sec_jobs"
      run_10sec_jobs
      # reset SECONDS
      SECONDS=0

      # check for minute change
      current_minute=`date +%M | bc`
      if [ ${current_minute} -ne ${last_minute} ]
      then
         # run every minute jobs
         logFx ${FUNCNAME[0]} 0 "minute change from ${last_minute} to ${current_minute} - calling run_minute_jobs"
         run_minute_jobs
         # reset last_minute
         last_minute=${current_minute}

         # check for hour change
         current_hour=`date +%H | bc`
         if [ ${current_hour} -ne ${last_hour} ]
         then
            # run every hour jobs
            logFx ${FUNCNAME[0]} 0 "hour change from ${last_hour} to ${current_hour} - calling run_hourly_jobs"
            run_hourly_jobs
            # reset last_minute
            last_hour=${current_hour}

            # check for day change
            current_day=`date +%j | bc`
            if [ ${current_day} -ne ${last_day} ]
            then
               # run every day jobs
               logFx ${FUNCNAME[0]} 0 "day change from ${last_day} to ${current_day} - calling run_daily_jobs"
               run_daily_jobs
               # reset last_day
               last_day=${current_day}
            fi
         fi
      fi
   fi
   sleep ${sleep_time}
done
