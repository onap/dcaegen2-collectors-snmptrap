#!/usr/bin/env bash
# -*- indent-tabs-mode: nil -*- # vi: set expandtab:
#
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

# basics
current_cmd=`basename $0`
current_module=`echo $current_cmd | cut -d"." -f1`

# get base_dir from current script invocation
bin_base_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
base_dir=`dirname ${bin_base_dir}`

snmptrapd_pid_file=${base_dir}/tmp/${current_module}.py.pid
scheduler_pid_file=${base_dir}/tmp/scheduler.sh.pid

start_dir=${base_dir}/bin

# global return code
#  - required because functions ultimately call log_msg, which
#    is to stdout, which conflicts with "echo <return_value>"
#    in the functions themselves
g_return=0

# include path to 3.6+ version of python that has required dependencies included
export PATH=/opt/app/python-3.6.1/bin:$PATH

# set location of SSL certificates
# export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt	# open source/external world
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt	# otherwise...

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

# expand search for python modules to include ./mod in current/runtime dir
export PYTHONPATH=${bin_base_dir}/mod:$PYTHONPATH

# PYTHONUNBUFFERED:
#    set PYTHONUNBUFFERED to a non-empty string to avoid output buffering;
#    comment out for runtime environments/better performance!
# export PYTHONUNBUFFERED="True"

# set location of config broker server overrride IF NEEDED
#
export CBS_SIM_JSON=${base_dir}/etc/snmptrapd.json

# misc
exit_after=1

# # # # # # # # # #
# log_msg - log messages to stdout in standard manner
# # # # # # # # # #
log_msg()
{
   msg=$*

   echo "`date +%Y-%m-%dT%H:%M:%S,%N | cut -c1-23` ${msg}"
}

#
# start process
#
start_process()
{
process_name=$1
pid_file=$2
exec_cmd=$3

   # check if exec_cmd has a pid_file
   if [ ! -r ${pid_file} ]
   then
      log_msg "Starting ${process_name}"
      stdout_fd=${base_dir}/logs/${process_name}.out
      if [ -f ${stdout_fd} ]
      then
         mv -f ${stdout_fd} ${stdout_fd}.bak
      fi
      ${exec_cmd} 2>&1 | tee -a ${base_dir}/logs/${process_name}.out &
      g_return=$?
      echo $! > ${pid_file}
   else
      pid=$(cat ${pid_file})
      if ps -p ${pid} > /dev/null
      then
         g_return=$?
         log_msg "${process_name} already running - PID ${pid}"
      else
         log_msg "PID file present, but no corresponding process.  Starting ${process_name}"
         ${exec_cmd} 2>&1 | tee -a ${base_dir}/logs/${process_name}.out &
         g_return=$?
         echo $! > ${pid_file}
      fi
   fi
}

# # # # # # # # # #
# Start the service
# # # # # # # # # #
start_service()
{
   # Hints for startup modifications:
   # _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

   # handy for debug (e.g. docker logs output)
   # log_msg "Runtime env present for ${current_module} placed in ${base_dir}/logs/${current_module}.out"
   env >>  ${base_dir}/logs/${current_module}.out

   # standard startup?  Use this:
   cmd="${PY_BINARY} ${base_dir}/bin/snmptrapd.py"
   # want tracing?  Use this:
   # cmd="${PY_BINARY} ./snmptrapd.py -v"
   # unbuffered io for logs? Use this:
   #     cmd="${PY_BINARY} -u ./snmptrapd.py"
   # fmdl: needs further research
   #     cmd="${PY_BINARY} -m trace --trackcalls ./snmptrapd.py"

   cd ${start_dir}

   #
   # scheduler
   #
   start_process scheduler ${scheduler_pid_file} "${bin_base_dir}/scheduler.sh"
   if [ ${g_return} -ne 0 ]
   then
       log_msg "ERROR!  Unable to start scheduler.  Check logs for details."
   fi

   #
   # snmptrapd
   #
   start_process ${current_module} ${snmptrapd_pid_file} "${cmd}"
   if [ ${g_return} -ne 0 ]
   then
       log_msg "ERROR!  Unable to start ${current_module}.  Check logs for details."
   fi
}

# # # # # # # # # #
# Stop the service
# # # # # # # # # #
stop_process()
{
process_name=$1
pid_file=$2

    if [ ! -r ${pid_file} ]
    then
        log_msg "PID file ${pid_file} does not exist or not readable - unable to stop ${process_name}"
        g_return=1
    else
        pid=$(cat ${pid_file})
        pgrep -f ${process_name} | grep "^${pid}" > /dev/null
        loc_return=$?
        if [ ${loc_return} -eq 0 ]
        then
            log_msg "Stopping ${process_name} PID ${pid}..."
            kill ${pid}
            g_return=$?
            if [ ${g_return} -eq 0 ]
            then
                log_msg "Stopped"
            else
                log_msg "ERROR while terminating ${process_name} PID ${pid} (is it not running or owned by another userID?)"
            fi
        else
            log_msg "${process_name} PID ${pid} not present - skipping"
        fi

        if [ -w ${pid_file} ]
        then
           rm -f ${pid_file}
        fi
    fi
}

# # # # # # # # # # # # # # #
# stop all snmptrapd services
# # # # # # # # # # # # # # #
stop_service()
{
   # scheduler
   #
   stop_process scheduler ${scheduler_pid_file}

   # snmptrapd
   #
   stop_process ${current_module} ${snmptrapd_pid_file}
}

# # # # # # # # # # # # # # #
# Check status of the service
# # # # # # # # # # # # # # #
status_process()
{
process_name=$1
pid_file=$2

    if [ -r ${pid_file} ]
    then
        pid=$(cat ${pid_file})
        pgrep -f ${process_name} | grep "^${pid}" > /dev/null
        loc_return=$?

        if [ ${loc_return} -eq 0 ]
        then
            log_msg "- ${process_name} running, PID ${pid}"
            # ps -f -p ${pid} -f | grep -v PID
            g_return=0
        else
            log_msg "ERROR! ${process_name} not running"
            g_return=1
        fi
   else
        log_msg "PID file ${pid_file} does not exist or not readable - unable to check status of ${process_name}"
        g_return=1
    fi
}

#
#
#
status_service()
{
   # scheduler
   #
   status_process scheduler  ${scheduler_pid_file}
   loc_return=${g_return}

   # snmptrapd
   #
   status_process ${current_module} ${snmptrapd_pid_file}
   loc_return=$((loc_return+g_return))
   if [ ${loc_return} -ne 0 ]
   then
      log_msg "Overall Status: CRITICAL - Required process(es) missing!"
   else
      log_msg "Overall Status: Normal"
   fi
}

# # # # # # # # # # # # # # # # #
# Signal process to reload config
# # # # # # # # # # # # # # # # #
reload_cfg()
{
    # only needed for snmptrapd
    if [ -r ${snmptrapd_pid_file} ]
    then
       pid=$(cat ${snmptrapd_pid_file})
       ps -p ${pid} > /dev/null 2>&1
       loc_return=$?
       if [ ${loc_return} ]
       then
          log_msg "Signaling ${current_module} PID ${pid} to request/read updated configs..."
          kill -USR1 ${pid}
          g_return=$?
          if [ ${g_return} -eq 0 ]
          then
              log_msg "...Signal complete."
          else
              log_msg "ERROR signaling ${current_module} (do you have permissions to do this?)"
          fi
       else
          log_msg "ERROR: ${current_module} PID ${pid} does not appear to be running."
       fi
    else
       log_msg "ERROR: ${snmptrapd_pid_file} does not exist - unable to signal for config re-read."
       g_return=1
    fi
}

# # # # # # # # # # # # # # #
# stop all snmptrapd services
# # # # # # # # # # # # # # #
version()
{
    exit_swt=$1

    version_fd=${base_dir}/etc/version.dat
    if [ -f ${version_fd} ]
    then
        version_string=`cat ${version_fd}`
        log_msg "${version_string}"
        ec=0
    else
        log_msg "ERROR: unable to determine version"
        ec=1
    fi

    if [ "${exit_swt}" = "${exit_after}" ]
    then
        exit ${ec}
    fi

}

# # # # # # # # # # # # #
# M A I N
# # # # # # # # # # # # #


case "$1" in
   "start")
          version
          start_service
          sleep 1
          status_service
          wait
          ;;
   "stop")
          version
          stop_service
          ;;
   "restart")
          version
          stop_service
          sleep 1
          start_service
          status_service
          ;;
   "status")
          version
          status_service
          ;;
   "reloadCfg")
          version
          reload_cfg
          ;;
   "version")
          version ${exit_after}
          ;;
   *)
          echo "Usage: ${current_cmd} {start|stop|restart|status|reloadCfg|version}"
          g_return=1
   esac

exit ${g_return}
