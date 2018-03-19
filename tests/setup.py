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

import argparse
import array
import asyncio
import collections
import datetime
import errno
import inspect
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
import trapd_settings
import trapd_settings as tds
import unicodedata
import uuid as uuid_mod
from collections import Counter
from onap_dcae_cbs_docker_client.client import get_config
from pysnmp.carrier.asyncio.dgram import udp, udp6
# from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
from trapd_exit import cleanup_and_exit
from trapd_file_utils import roll_all_logs, open_eelf_logs, roll_file, open_file, close_file
from trapd_get_cbs_config import get_cbs_config
from trapd_http_session import init_session_obj
from trapd_logging import ecomp_logger, stdout_logger
from trapd_logging import stdout_logger
from trapd_runtime_pid import save_pid, rm_pid

install_reqs = parse_requirements("requirements.txt", session=PipSession())
reqs = [str(ir.req) for ir in install_reqs]

setup(
    name = "dcaegen2-collectors-snmptrap",
    description = "snmp trap receiver for ONAP docker image",
    version = "1.3.0",
    packages=find_packages(),
    author = "Dave L",
    author_email = "dl3158@att.com",
    license='Apache 2',
    keywords = "",
    url = "",
    install_requires=reqs
)
