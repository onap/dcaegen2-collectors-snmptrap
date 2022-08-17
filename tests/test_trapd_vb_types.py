# ============LICENSE_START=======================================================
# Copyright (c) 2019-2022 AT&T Intellectual Property. All rights reserved.
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

import unittest

import trapd_vb_types
import trapd_settings as tds


class test_trapd_vb_types(unittest.TestCase):
    """
    Test snmpv3 module
    """

    @classmethod
    def setUpClass(cls):
        tds.init()


    def test_trapd_vb_type_conversion_integer32(self):
        """
        Test that pysnmp varbind types Integer converts
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Integer32"), "integer")


    def test_trapd_vb_type_conversion_integer(self):
        """
        Test that pysnmp varbind types Integer converts
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Integer"), "integer")


    def test_trapd_vb_type_conversion_gauge32(self):
        """
        Test that pysnmp varbind types Integer converts
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Gauge32"), "unsigned")


    def test_trapd_vb_type_conversion_counter32(self):
        """
        Test that pysnmp varbind types Integer converts
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Counter32"), "counter32")


    def test_trapd_vb_type_conversion_octetstring(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("OctetString"), "octet")


    def test_trapd_vb_type_conversion_py_type_5(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("py_type_5"), "hex")


    def test_trapd_vb_type_conversion_py_type_6(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("py_type_6"), "decimal")


    def test_trapd_vb_type_conversion_null(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Null"), "null")


    def test_trapd_vb_type_conversion_objectidentifier(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("ObjectIdentifier"), "oid")


    def test_trapd_vb_type_conversion_timeticks(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("TimeTicks"), "timeticks")


    def test_trapd_vb_type_conversion_ipaddress(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("IpAddress"), "ipaddress")


    def test_trapd_vb_type_conversion_bits(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("Bits"), "bits")


    def test_trapd_vb_type_conversion_invalid(self):
        """
        Test that pysnmp varbind types convert accurately
        """
        # should return default of octet if not defined
        self.assertEqual(trapd_vb_types.pysnmp_to_netsnmp_varbind_convert("noSuchVarbindType"), "octet")


if __name__ == "__main__": # pragma: no cover
    unittest.main(verbosity=2)
