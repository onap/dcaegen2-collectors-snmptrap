# org.onap.dcae
# ================================================================================
# Copyright (c) 2017 AT&T Intellectual Property. All rights reserved.
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

import argparse
import array
import asyncio
import collections
import datetime
import errno
from pysnmp.carrier.asyncio.dgram import udp, udp6
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
import json
import logging
import logging.handlers
import os
import pprint
import re
import requests
import signal
import socket
import string
import sys
import time
import traceback
from trapd_dmaap_config import read_dmaap_config
from trapd_exit import cleanup_and_exit
from trapd_http_session import init_session_obj
from trapd_perm_status import log_to_perm_status
from trapd_runtime_pid import save_pid, rm_pid
from trapd_trap_config import read_trap_config
from trapd_yaml_config import read_yaml_config
import unicodedata
import uuid as uuid_mod
import yaml

install_reqs = parse_requirements("requirements.txt", session=PipSession())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name = "onap_dcae_cbs_docker_client",
    description = "snmp trap receiver for a DCAE docker image",
    version = "1.2",
    packages=find_packages(),
    author = "Dave L",
    author_email = "dl3158@att.com",
    license='Apache 2',
    keywords = "",
    url = "",
    install_requires=reqs
)
