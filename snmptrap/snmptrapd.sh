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

# get to where we are supposed to be for startup
cd /opt/app/snmptrap/bin

# include path to 3.6+ version of python that has required dependencies included
export PATH=/opt/app/python-3.6.1/bin:$PATH

# expand search for python modules to include ./mod in runtime dir
export PYTHONPATH=./mod:./:$PYTHONPATH

# set location of SSL certificates
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt

# PYTHONUNBUFFERED:
#    set PYTHONUNBUFFERED to a non-empty string to avoid output buffering; 
#    comment out for runtime environments/better performance!
# export PYTHONUNBUFFERED="True"

# set location of config broker server overrride IF NEEDED
#
export CBS_SIM_JSON=../etc/snmptrapd.json

# want tracing?  Use this:
# python -m trace --trackcalls snmptrapd.py -v

# want verbose logging?  Use this:
# python snmptrapd.py -v

# standard startup?  Use this:
# python snmptrapd.py

# unbuffered io for logs and verbose logging? Use this:
python -u snmptrapd.py -v
