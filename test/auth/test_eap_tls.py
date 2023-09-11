# -------------------------------------------------------------------------
# Copyright 2023-2023, Boling Consulting Solutions, bcsw.net
#
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
# limitations under the License
# -------------------------------------------------------------------------
# pylint: skip-file

import unittest

from mocks.util import assertGeneratedFrameEquals

from auth.eap import EapCode, EapType, EAP, EapRequest
from auth.eap_tls import EapTls


class TestEapTls(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls._eap_id = 0x78
        cls._eap_flags = EapTls.START_FLAG_MASK
        # TODO: Is there a limit on type_data size?

    def test_RequestFrameSerialize(self):
        expected = f"01{self._eap_id:02x}00060d20"
        tls = EapTls(self._eap_flags)

        eap = EapRequest(EapType.EAP_IDENTITY, tls, eap_id=self._eap_id)
        assertGeneratedFrameEquals(self, eap.pack(), expected)
        # TODO: Test length flags as well

    def test_RequestFrameDecode(self):
        # Construct frame
        frame = f"01{self._eap_id:02x}00060d20"
        eap = EAP.parse(bytes.fromhex(frame))

        self.assertIsInstance(eap, EapRequest)
        self.assertEqual(eap.eap_code, EapCode.EAP_REQUEST)

        # layers = eap.layers
        # self.assertIsInstance(layers, tuple)
        # self.assertEqual(len(layers), 1)
        # identity = layers[0]
        # TODO: Eventually make type data a layer?  Maybe, maybe not...
        import sys
        print(f"EAP: {eap}", file=sys.stderr)
        print(f"typedaa: {eap.type_data}", file=sys.stderr)
        tls = eap.type_data
        # self.assertIsInstance(tls, EapTls)

        self.assertEqual(tls.eap_type, EapType.EAP_TLS)
        self.assertEqual(tls.flags, self._flags)
        self.assertEqual(tls.tls_length, 0)
        self.assertIsNone(tls.tls_data)

        # TODO: See EapIdentify docstring.  Support test prompt string passing
        # TODO: See EapIdentify docstring.  Support test for passing optional attrributes

    # def test_ResponseFrameSerialize(self):
    #     expected = f"02{self._eap_id:02x}00150175736572406578616d706c652e6f7267"
    #
    #     identity = EapIdentity(type_data=self._ident)
    #     eap = EapResponse(EapType.EAP_IDENTITY, identity, eap_id=self._eap_id)
    #     assertGeneratedFrameEquals(self, eap.pack(), expected)
    #
    # def test_ResponseFrameDecode(self):
    #     # Construct frame
    #     frame = f"02{self._eap_id:02x}00150175736572406578616d706c652e6f7267"
    #     eap = EAP.parse(bytes.fromhex(frame))
    #
    #     self.assertIsInstance(eap, EapResponse)
    #
    #     identity = eap.type_data
    #     self.assertEqual(identity.eap_type, EapType.EAP_IDENTITY)
    #     self.assertEqual(identity.type_data, self._ident)


if __name__ == '__main__':
    unittest.main()
