#!/usr/bin/env bash
#
# ============LICENSE_START=======================================================
# org.onap.dcae
# ================================================================================
# Copyright (c) 2017-2018 AT&T Intellectual Property. All rights reserved.
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
# ECOMP is a trademark and service mark of AT&T Intellectual Property.
#

# basics
current_cmd=`basename $0`
current_module=`echo $current_cmd | cut -d"." -f1`

# FMDL:: need to pick up these values from json config, but it isn't
#        present at startup
base_dir=/opt/app/snmptrap
pid_file=${base_dir}/tmp/${current_module}.py.pid
start_dir=${base_dir}/bin

# include path to 3.6+ version of python that has required dependencies included
export PATH=/opt/app/python-3.6.1/bin:$PATH

# set location of SSL certificates
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt

# get to where we are supposed to be for startup
cd /opt/app/snmptrap/bin

# expand search for python modules to include ./mod in current/runtime dir
export PYTHONPATH=./mod:./:$PYTHONPATH

# PYTHONUNBUFFERED:
#    set PYTHONUNBUFFERED to a non-empty string to avoid output buffering; 
#    comment out for runtime environments/better performance!
# export PYTHONUNBUFFERED="True"

# set location of config broker server overrride IF NEEDED
#
export CBS_SIM_JSON=../etc/snmptrapd.json

# # # # # # # # # # 
# log_msg - log messages to stdout in standard manner
# # # # # # # # # # 
log_msg()
{
   msg=$*

   printf "`date +%Y-%m-%dT%H:%M:%S,%N | cut -c1-23` ${msg}"
}

# # # # # # # # # # 
# Start the service
# # # # # # # # # # 
start_service()
{
   # Hints for startup modifications:
   # _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
   # standard startup?  Use this:
   cmd="python ./snmptrapd.py"
   # want tracing?  Use this:
   #     "python -m trace --trackcalls snmptrapd.py"
   # unbuffered io for logs? Use this:
   #     "python -u snmptrapd.py"

   cd ${start_dir}

   # check for process already running
   if [ -r ${pid_file} ]
   then
      pid=$(cat ${pid_file})
      if ps -p ${pid} > /dev/null
      then
         printf "${current_module} already running - PID ${pid}\n"
         return 0
      fi
   fi

   # FMDL:: do this in snmptrapd.py at startup
   # roll log if present at startup
   # if [ -f ${LOGFILE} ]
   # then
      # mv -f ${LOGFILE} ${LOGFILE}.`date +%h-%m-%Y_%H:%M:%S`
   # fi

   log_msg "Starting ${current_module}...  "
   eval ${cmd}
   return_code=$?

   if [ ${return_code} -eq 0 ]
   then
       log_msg "Started.\n"
   else
       log_msg "\nERROR!  Unable to start ${current_module}.  Check logs for details.\n"
   fi

   return ${return_code}

}

# # # # # # # # # # 
# Stop the service
# # # # # # # # # # 
stop_service()
{
    if [ ! -r ${pid_file} ]
    then
        log_msg "PID file ${pid_file} does not exist or not readable - unable to stop specific instance of ${current_module}.\n"
        log_msg "Diagnose further at command line as needed.\n"
        return_code=1
    else
        pid=$(cat ${pid_file})
        log_msg "Stopping ${current_module} PID ${pid}...\n"
        kill ${pid}
        if [ $? -ne 0 ]
        then
            log_msg "\nERROR while trying to terminate ${current_module} PID ${pid} (is it not running or owned by another userID?)"
            log_msg "\nDiagnose further at command line as needed."
            return_code=$?
            if [ -w ${pid_file} ]
            then
                rm -f ${pid_file}
            fi
        else
            log_msg "Stopped\n"
            if [ -w ${pid_file} ]
            then
                rm -f ${pid_file}
            fi
            return_code=0
        fi
    fi

    return ${return_code}
}

# # # # # # # # # # # # # # #
# Check status of the service
# # # # # # # # # # # # # # #
status_service()
{
    if [ -r ${pid_file} ]
    then
        pid=$(cat ${pid_file})
        pgrep -a python | grep ${current_module} | grep "^${pid}" > /dev/null
        return_code=$?

        if [ ${return_code} -eq 0 ]
        then
            log_msg "Status: ${current_module} running\n"
            ps -p ${pid} -f | grep -v PID
            return_code=0
        else
            log_msg "Status: ERROR! ${current_module} not running.\n"
            return_code=1
        fi
   else
        log_msg "PID file ${pid_file} does not exist or not readable - unable to check status of ${current_module}\n"
        log_msg "Diagnose further at command line as needed.\n"
        return 1
    fi

    return ${return_code}
}

# # # # # # # # # # # # # # # # #
# Signal process to reload config
# # # # # # # # # # # # # # # # #
reload_cfg()
{
    if [ -r ${pid_file} ]
    then
       pid=$(cat ${pid_file})
       ps -p ${pid} > /dev/null 2>&1
       ret=$?
       if [ ${ret} ]
       then
          log_msg "Signaling ${current_module} PID ${pid} to request/read updated configs...\n"
          kill -USR1 ${pid}
          return_code=$?
          if [ ${return_code} -eq 0 ]
          then
              log_msg "...Signal complete.\n"
          else
              log_msg "\nERROR signaling ${current_module} - diagnose further at the command line.\n"
          fi
       else
          log_msg "\nERROR: ${current_module} PID ${pid} does not appear to be running.\n"
          return_code=1
       fi
    else
       log_msg "\nERROR: ${current_module} pid_file ${pid_file} does not exist - unable to signal for config re-read.\n"
       return_code=1
    fi

    return ${return_code}
}

# # # # # # # # # # # # #
# M A I N
# # # # # # # # # # # # #

case "$1" in
   "start")
          start_service
          exit $?
          ;;
   "stop") 
          stop_service
          exit $?
          ;;
   "restart")
          stop_service
          sleep 1
          start_service
          exit $?
          ;;
   "status") 
          status_service
          exit $?
          ;;
   "reloadCfg")
          reload_cfg
          exit $?
          ;;
   *)
          printf "\nUsage: ${current_cmd} {start|stop|restart|status|rollLog|reloadCfg}\n"
          exit 1
   esac
