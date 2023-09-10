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

import sys
import unittest

from mocks.util import assertGeneratedFrameEquals

from auth.eap import EapCode, EapType, EAP, EapRequest, EapResponse, EapSuccess, EapFailure, EapInitiate, \
    EapFinish, EapIdentity, EapLegacyNak, EapMd5Challenge


class TestEAP(unittest.TestCase):

    def test_EAPCode(self):
        # Change underscores to spaces
        valid_codes = {1, 2, 3, 4, 5, 6}
        for code in valid_codes:
            self.assertTrue(EapCode.has_value(code))

            name = EapCode(code).name()
            self.assertFalse('_' in name)

        for enumeration in (EapCode.EAP_REQUEST,
                            EapCode.EAP_RESPONSE,
                            EapCode.EAP_SUCCESS,
                            EapCode.EAP_FAILURE,
                            EapCode.EAP_INITIATE,
                            EapCode.EAP_FINISH):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = EapCode(code)
                    print(f"test_EAPCode: Code {code} did not throw an assert", file=sys.stderr)


class TestEapRequest(unittest.TestCase):

    @classmethod
    def setUp(cls):
        pass

    def testDefaults(self):
        pass
        # eapol = EapRequest()
        # self.assertEqual(eapol.version, 2)
        # self.assertEqual(eapol.packet_type, EAPOLPacketType.EAPOL_START)
        # self.assertIsNone(eapol.length)
        # self.assertIsInstance(eapol.tlvs, tuple)
        # self.assertEqual(len(eapol.tlvs), 0)

    def test_FrameSerialize(self):
        pass
        # expected = f"{version:02x}010000"
        # eapol = EapRequest(version=version)
        # assertGeneratedFrameEquals(self, eapol.pack(), expected)

        # TODO: Add serialize 'failure' cases

    def test_FrameDecode(self):
        pass
        # Construct frame
        # frame = f"{version:02x}010000"
        # eap = EAP.parse(bytes.fromhex(frame))
        #
        # self.assertIsNotNone(eapol)
        # self.assertEqual(eapol.version, version)
        # self.assertEqual(eapol.packet_type, EAPOLPacketType.EAPOL_START)
        # self.assertEqual(eapol.length, 0)
        # self.assertIsInstance(eapol.tlvs, tuple)
        # self.assertEqual(len(eapol.tlvs), 0)

        # TODO: Add decode 'failure' cases


class TestEapResponse(unittest.TestCase):

    @classmethod
    def setUp(cls):
        pass

    def testDefaults(self):
        pass
        # eapol = EapRequest()
        # self.assertEqual(eapol.version, 2)
        # self.assertEqual(eapol.packet_type, EAPOLPacketType.EAPOL_START)
        # self.assertIsNone(eapol.length)
        # self.assertIsInstance(eapol.tlvs, tuple)
        # self.assertEqual(len(eapol.tlvs), 0)

    def test_FrameSerialize(self):
        pass
        # expected = f"{version:02x}010000"
        # eapol = EapRequest(version=version)
        # assertGeneratedFrameEquals(self, eapol.pack(), expected)

        # TODO: Add serialize 'failure' cases

    def test_FrameDecode(self):
        pass
        # Construct frame
        # frame = f"{version:02x}010000"
        # eap = EAP.parse(bytes.fromhex(frame))
        #
        # self.assertIsNotNone(eapol)
        # self.assertEqual(eapol.version, version)
        # self.assertEqual(eapol.packet_type, EAPOLPacketType.EAPOL_START)
        # self.assertEqual(eapol.length, 0)
        # self.assertIsInstance(eapol.tlvs, tuple)
        # self.assertEqual(len(eapol.tlvs), 0)

        # TODO: Add decode 'failure' cases


class TestEapSuccess(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls._eap_id = 0x78

    def testDefaults(self):
        eap = EapSuccess()
        self.assertEqual(eap.eap_code, EapCode.EAP_SUCCESS)
        self.assertEqual(eap.eap_id, 256)
        self.assertIsNone(eap.length)

    def test_FrameSerialize(self):
        expected = "03780004"
        eap = EapSuccess(eap_id=self._eap_id)
        assertGeneratedFrameEquals(self, eap.pack(), expected)

        # TODO: Add serialize 'failure' cases

    def test_FrameDecode(self):
        # Construct frame
        frame = f"03{self._eap_id:02x}0004"
        eap = EAP.parse(bytes.fromhex(frame))

        self.assertIsInstance(eap, EapSuccess)
        self.assertEqual(eap.eap_code, EapCode.EAP_SUCCESS)
        self.assertEqual(eap.eap_id, self._eap_id)
        self.assertEqual(eap.length, 4)

        # layers = eap.layers
        # self.assertIsInstance(layers, tuple)
        # self.assertEqual(len(layers), 0)

        # TODO: Add decode 'failure' cases


class TestEapFailure(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls._eap_id = 0x78

    def testDefaults(self):
        eap = EapFailure()
        self.assertEqual(eap.eap_code, EapCode.EAP_FAILURE)
        self.assertEqual(eap.eap_id, 256)
        self.assertIsNone(eap.length)

    def test_FrameSerialize(self):
        expected = "04780004"
        eap = EapFailure(eap_id=self._eap_id)
        assertGeneratedFrameEquals(self, eap.pack(), expected)

        # TODO: Add serialize 'failure' cases

    def test_FrameDecode(self):
        # Construct frame
        frame = f"04{self._eap_id:02x}0004"
        eap = EAP.parse(bytes.fromhex(frame))

        self.assertIsInstance(eap, EapFailure)
        self.assertEqual(eap.eap_code, EapCode.EAP_FAILURE)
        self.assertEqual(eap.eap_id, self._eap_id)
        self.assertEqual(eap.length, 4)

        # layers = eap.layers
        # self.assertIsInstance(layers, tuple)
        # self.assertEqual(len(layers), 0)

        # TODO: Add decode 'failure' cases


class TestEapInitiate(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls._eap_id = 0x78

    def testDefaults(self):
        with self.assertRaises(NotImplementedError):
            eap = EapInitiate()
            self.assertEqual(eap.eap_code, EapCode.EAP_FAILURE)
            self.assertEqual(eap.eap_id, 256)
            self.assertIsNone(eap.length)

    def test_FrameSerialize(self):
        with self.assertRaises(NotImplementedError):
            expected = ""
            eap = EapInitiate(eap_id=self._eap_id)
            assertGeneratedFrameEquals(self, eap.pack(), expected)

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


class TestEapFinish(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls._eap_id = 0x78

    def testDefaults(self):
        with self.assertRaises(NotImplementedError):
            eap = EapFinish()
            self.assertEqual(eap.eap_code, EapCode.EAP_FAILURE)
            self.assertEqual(eap.eap_id, 256)
            self.assertIsNone(eap.length)

    def test_FrameSerialize(self):
        with self.assertRaises(NotImplementedError):
            expected = ""
            _eap = EapFinish()
            eap = EapFinish(eap_id=self._eap_id)
            assertGeneratedFrameEquals(self, eap.pack(), expected)

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


class TestEapPacket(unittest.TestCase):
    def test_EAPType(self):
        # Change underscores to spaces
        valid_codes = {1, 3, 4, 5, 6, 13, 21, 25}

        for code in valid_codes:
            self.assertTrue(EapType.has_value(code))

            name = EapType(code).name()
            self.assertFalse('_' in name)

        for enumeration in (EapType.EAP_IDENTITY,
                            EapType.EAP_LEGACY_NAK,
                            EapType.EAP_MD5_CHALLENGE,
                            EapType.EAP_ONE_TIME_PASSWORD,
                            EapType.EAP_GENERIC_TOKEN_CARD,
                            EapType.EAP_TLS,
                            EapType.EAP_TTLS,
                            EapType.EAP_PEAP):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = EapType(code)
                    print(f"test_EAPType: Code {code} did not throw an assert", file=sys.stderr)


class TestEapIdentity(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls._eap_id = 0x78
        cls._ident = bytes("user@example.org", "utf-8")
        # TODO: Is there a limit on type_data size?

    def testDefaults(self):
        eap = EapIdentity()
        self.assertEqual(eap.eap_type, EapType.EAP_IDENTITY)
        self.assertEqual(eap.type_data, b"")

    def test_RequestFrameSerialize(self):
        expected = f"01{self._eap_id:02x}000501"
        identity = EapIdentity()

        eap = EapRequest(EapType.EAP_IDENTITY, identity, eap_id=self._eap_id)
        assertGeneratedFrameEquals(self, eap.pack(), expected)

    def test_RequestFrameDecode(self):
        # Construct frame
        frame = f"01{self._eap_id:02x}000501"
        eap = EAP.parse(bytes.fromhex(frame))

        self.assertIsInstance(eap, EapRequest)
        self.assertEqual(eap.eap_code, EapCode.EAP_REQUEST)

        # layers = eap.layers
        # self.assertIsInstance(layers, tuple)
        # self.assertEqual(len(layers), 1)
        # identity = layers[0]
        # TODO: Eventually make type data a layer?  Maybe, maybe not...
        identity = eap.type_data
        self.assertIsInstance(identity, EapIdentity)

        self.assertEqual(identity.eap_type, EapType.EAP_IDENTITY)
        self.assertEqual(identity.type_data, b"")
        # TODO: See EapIdentify docstring.  Support test prompt string passing
        # TODO: See EapIdentify docstring.  Support test for passing optional attrributes

    def test_ResponseFrameSerialize(self):
        expected = f"02{self._eap_id:02x}00150175736572406578616d706c652e6f7267"

        identity = EapIdentity(type_data=self._ident)
        eap = EapResponse(EapType.EAP_IDENTITY, identity, eap_id=self._eap_id)
        assertGeneratedFrameEquals(self, eap.pack(), expected)

    def test_ResponseFrameDecode(self):
        # Construct frame
        frame = f"02{self._eap_id:02x}00150175736572406578616d706c652e6f7267"
        eap = EAP.parse(bytes.fromhex(frame))

        self.assertIsInstance(eap, EapResponse)

        identity = eap.type_data
        self.assertEqual(identity.eap_type, EapType.EAP_IDENTITY)
        self.assertEqual(identity.type_data, self._ident)


class TestLegacyNak(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls._eap_id = 0x78
        cls._ident = bytes("user@example.org", "utf-8")
        cls._desired_auth = (EapType.EAP_MD5_CHALLENGE,)
        # TODO: Is there a limit on type_data size?

    def testDefaults(self):
        eap = EapLegacyNak()
        self.assertEqual(eap.eap_type, EapType.EAP_LEGACY_NAK)
        self.assertEqual(eap.desired_auth, tuple())

    def test_ResponseFrameSerialize(self):
        expected = f"02{self._eap_id:02x}00060304"

        identity = EapLegacyNak(desired_auth=self._desired_auth)
        eap = EapResponse(EapType.EAP_LEGACY_NAK, identity, eap_id=self._eap_id)
        assertGeneratedFrameEquals(self, eap.pack(), expected)
        # TODO: Test other desired auth combinations

    def test_ResponseFrameDecode(self):
        # Construct frame
        frame = f"02{self._eap_id:02x}00060304"
        eap = EAP.parse(bytes.fromhex(frame))

        self.assertIsInstance(eap, EapResponse)

        identity = eap.type_data
        self.assertIsInstance(identity, EapLegacyNak)
        self.assertEqual(identity.eap_type, EapType.EAP_LEGACY_NAK)
        self.assertEqual(identity.desired_auth, self._desired_auth)

        # TODO: Test other desired auth combinations


class TestEapMd5Challenge(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls._eap_id = 0x78
        cls._challenge = bytes("b6ef2b639c94f765f8c039a468bc0da8", "utf-8")
        cls._extra_data = b""

    def testDefaults(self):
        eap = EapMd5Challenge()
        self.assertEqual(eap.eap_type, EapType.EAP_MD5_CHALLENGE)
        self.assertEqual(eap.challenge, b"")
        self.assertEqual(eap.extra_data, b"")

    def test_RequestFrameSerialize(self):
        expected = f"01{self._eap_id:02x}00160410b6ef2b639c94f765f8c039a468bc0da8"

        md5 = EapMd5Challenge(challenge=self._challenge, extra_data=self._extra_data)
        eap = EapRequest(EapType.EAP_MD5_CHALLENGE, md5, eap_id=self._eap_id)
        assertGeneratedFrameEquals(self, eap.pack(), expected)
        # TODO: Test other combinations

    def test_RequestFrameDecode(self):
        # Construct frame
        frame = f"01{self._eap_id:02x}00160410b6ef2b639c94f765f8c039a468bc0da8"
        eap = EAP.parse(bytes.fromhex(frame))

        self.assertIsInstance(eap, EapRequest)

        md5 = eap.type_data
        self.assertIsInstance(md5, EapMd5Challenge)
        self.assertEqual(md5.eap_type, EapType.EAP_MD5_CHALLENGE)
        self.assertEqual(md5.challenge, self._challenge)
        self.assertEqual(md5.extra_data, self._extra_data)

    # def test_ResponseFrameSerialize(self):
    #     expected = f"02{self._eap_id:02x}00160410c914a629540dae16de664c2a5013d832"
    #
    #     identity = EapMd5Challenge(desired_auth=self._desired_auth)
    #     eap = EapResponse(EapType.EAP_MD5_CHALLENGE, identity, eap_id=self._eap_id)
    #     assertGeneratedFrameEquals(self, eap.pack(), expected)
    #     # TODO: Test other combinations
    #
    # def test_ResponseFrameDecode(self):
    #     # Construct frame
    #     frame = f"02{self._eap_id:02x}00160410c914a629540dae16de664c2a5013d832"
    #     eap = EAP.parse(bytes.fromhex(frame))
    #
    #     self.assertIsInstance(eap, EapResponse)
    #
    #     identity = eap.type_data
    #     self.assertIsInstance(identity, EapMd5Challenge)
    #     self.assertEqual(identity.eap_type, EapType.EAP_MD5_CHALLENGE)
    #     self.assertEqual(identity.desired_auth, self._desired_auth)
    #
    #     # TODO: Test other combinations

if __name__ == '__main__':
    unittest.main()
