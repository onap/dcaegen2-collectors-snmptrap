# ============LICENSE_START=======================================================
# Copyright (c) 2019-2020 AT&T Intellectual Property. All rights reserved.
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

import pytest
import json
import unittest
import os

from onap_dcae_cbs_docker_client.client import get_config
from trapd_exit import cleanup_and_exit
from trapd_io import stdout_logger, ecomp_logger
import trapd_settings as tds
import trapd_vb_types

from pysnmp.entity import engine, config
 
class test_trapd_vb_types(unittest.TestCase):
    """
    Test snmpv3 module
    """

    good_varbind_types = ["Integer", "Unsigned32", "Counter32", "OctetString", "ObjectIdentifier", "TimeTicks", "IpAddress"]

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types Integer converts
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Integer32")
        self.assertEqual(result, "integer")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types Integer converts
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Integer")
        self.assertEqual(result, "integer")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types Integer converts
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Gauge32")
        self.assertEqual(result, "unsigned")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types Integer converts
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Counter32")
        self.assertEqual(result, "counter32")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("OctetString")
        self.assertEqual(result, "octet")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("py_type_5")
        self.assertEqual(result, "hex")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("py_type_6")
        self.assertEqual(result, "decimal")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Null")
        self.assertEqual(result, "null")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("ObjectIdentifier")
        self.assertEqual(result, "oid")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("TimeTicks")
        self.assertEqual(result, "timeticks")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("IpAddress")
        self.assertEqual(result, "ipaddress")

    def trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Bits")
        self.assertEqual(result, "bits")

    def trapd_vb_type_conversion_invalid(self):
        """
        Test that pysnmp varbind types convert accurately
        """

        result = trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("noSuchVarbindType")
        # should return default of octet if not defined
        self.assertEqual(result, "octet")

 
if __name__ == '__main__':
    unittest.main()
