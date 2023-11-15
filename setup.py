# ============LICENSE_START=======================================================
# Copyright (c) 2017-2022 AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2021 Deutsche Telekom. All rights reserved.
# Copyright (c) 2023 J. F. Lucas.  All rights reserved.
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

import os
import string
import sys
import setuptools
from setuptools import setup, find_packages


setup(
    name="snmptrap",
    description="snmp trap receiver for ONAP docker image",
    version="2.0.8",
    packages=find_packages(),
    install_requires=["pysnmp==4.4.12", "pyasn1==0.4.8" "requests==2.18.3", "onap_dcae_cbs_docker_client==2.2.1", "pyyaml"],
    author="Dave L",
    author_email="dl3158@att.com",
    license="Apache 2",
    keywords="",
    url="",
)
