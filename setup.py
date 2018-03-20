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

import os
import string
import sys

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
