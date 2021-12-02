# ============LICENSE_START=======================================================
# Copyright (c) 2018-2021 AT&T Intellectual Property. All rights reserved.
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

from pysnmp.hlapi import *
from pysnmp import debug

# debug.setLogger(debug.Debug('msgproc'))

iters = range(0, 10, 1)
for i in iters:
    errorIndication, errorStatus, errorIndex, varbinds = next(
        sendNotification(
            SnmpEngine(),
            CommunityData("not_public"),
            UdpTransportTarget(("localhost", 6164)),
            ContextData(),
            "trap",
            [
                ObjectType(ObjectIdentity(".1.3.6.1.4.1.999.1"), OctetString("test trap - ignore")),
                ObjectType(ObjectIdentity(".1.3.6.1.4.1.999.2"), OctetString("ONAP pytest trap")),
            ],
        )
    )

    if errorIndication:
        print(errorIndication)
    else:
        print("successfully sent first trap example, number %d" % i)

for i in iters:
    errorIndication, errorStatus, errorIndex, varbinds = next(
        sendNotification(
            SnmpEngine(),
            CommunityData("public"),
            UdpTransportTarget(("localhost", 6164)),
            ContextData(),
            "trap",
            NotificationType(ObjectIdentity(".1.3.6.1.4.1.74.2.46.12.1.1")).addVarBinds(
                (".1.3.6.1.4.1.999.1", OctetString("ONAP pytest trap - ignore (varbind 1)")),
                (".1.3.6.1.4.1.999.2", OctetString("ONAP pytest trap - ignore (varbind 2)")),
            ),
        )
    )

    if errorIndication:
        print(errorIndication)
    else:
        print("successfully sent second trap example, number %d" % i)
