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

from auth.eapol import EAPOL, EAPOLPacketType, EapolStart, EapolLogoff, EapolKey, \
    EapolEncapsulatedAsfAlert, EapolMKA, EapolAnnouncementGeneric, EapolAnnouncementSpecific, \
    EapolAnnouncmentReq


class TestEapol(unittest.TestCase):
    def test_EAPOLPacketType(self):
        # Change underscores to spaces
        valid_codes = {0, 1, 2, 3, 4, 5, 6, 7, 8}
        for code in valid_codes:
            self.assertTrue(EAPOLPacketType.has_value(code))

            name = EAPOLPacketType(code).name()
            self.assertFalse('_' in name)

        for enumeration in (EAPOLPacketType.EAPOL_EAP,
                            EAPOLPacketType.EAPOL_START,
                            EAPOLPacketType.EAPOL_LOGOFF,
                            EAPOLPacketType.EAPOL_KEY,
                            EAPOLPacketType.EAPOL_ENCAPSULATED_ASF_ALERT,
                            EAPOLPacketType.EAPOL_MKA,
                            EAPOLPacketType.EAPOL_ANNOUNCMENT_GENERIC,
                            EAPOLPacketType.EAPOL_ANNOUNCMENT_SPECIFIC,
                            EAPOLPacketType.EAPOL_ANNOUNCMENT_REQ):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = EAPOLPacketType(code)
                    print(f"test_EAPOLPacketType: Code {code} did not throw an assert", file=sys.stderr)


class TestEapolEAP(unittest.TestCase):
    def testDefaults(self):
        # TODO: Add test cases
        pass

    def test_FrameSerialize(self):
        # TODO: Add test cases
        pass

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


class TestEapolStart(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.versions = (1, 2, 3)

    def testDefaults(self):
        eapol = EapolStart()
        self.assertEqual(eapol.version, 2)
        self.assertEqual(eapol.EtherType(), 0x888e)
        self.assertEqual(eapol.packet_type, EAPOLPacketType.EAPOL_START)
        self.assertIsNone(eapol.length)
        self.assertIsInstance(eapol.tlvs, tuple)
        self.assertEqual(len(eapol.tlvs), 0)

    def test_FrameSerialize(self):
        for version in self.versions:
            expected = f"{version:02x}010000"
            eapol = EapolStart(version=version)
            assertGeneratedFrameEquals(self, eapol.pack(), expected)

        # TODO: Add test cases that have TLVs for version 3
        # TODO: Add serialize 'failure' cases

    def test_FrameDecode(self):
        for version in self.versions:
            # Construct frame
            frame = f"{version:02x}010000"
            eapol = EAPOL.parse(bytes.fromhex(frame))

            self.assertIsNotNone(eapol)
            self.assertEqual(eapol.version, version)
            self.assertEqual(eapol.packet_type, EAPOLPacketType.EAPOL_START)
            self.assertEqual(eapol.length, 0)
            self.assertIsInstance(eapol.tlvs, tuple)
            self.assertEqual(len(eapol.tlvs), 0)

        # TODO: Add test cases that have TLVs for version 3
        # TODO: Add decode 'failure' cases


class TestEapolLogoff(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.versions = (1, 2, 3)

    def testDefaults(self):
        eapol = EapolLogoff()
        self.assertEqual(eapol.version, 2)
        self.assertEqual(eapol.EtherType(), 0x888e)
        self.assertEqual(eapol.packet_type, EAPOLPacketType.EAPOL_LOGOFF)
        self.assertIsNone(eapol.length)

    def test_FrameSerialize(self):
        for version in self.versions:
            expected = f"{version:02x}020000"
            eapol = EapolLogoff(version=version)
            assertGeneratedFrameEquals(self, eapol.pack(), expected)

        # TODO: Add serialize 'failure' cases

    def test_FrameDecode(self):
        for version in self.versions:
            # Construct frame
            frame = f"{version:02x}020000"
            eapol = EAPOL.parse(bytes.fromhex(frame))

            self.assertIsNotNone(eapol)
            self.assertEqual(eapol.version, version)
            self.assertEqual(eapol.packet_type, EAPOLPacketType.EAPOL_LOGOFF)
            self.assertEqual(eapol.length, 0)

        # TODO: Add decode 'failure' cases


class TestEapolKey(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.versions = (1, 2, 3)

    def testDefaults(self):
        with self.assertRaises(NotImplementedError):
            _eapol = EapolKey()

    def test_FrameSerialize(self):
        for version in self.versions:
            with self.assertRaises(NotImplementedError):
                _eapol = EapolKey(version=version)

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


class TestEapolEncapsulatedAsfAlert(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.versions = (1, 2, 3)

    def testDefaults(self):
        with self.assertRaises(NotImplementedError):
            _eapol = EapolEncapsulatedAsfAlert()

    def test_FrameSerialize(self):
        for version in self.versions:
            with self.assertRaises(NotImplementedError):
                _eapol = EapolEncapsulatedAsfAlert(version=version)

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


class TestEapolMKA(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.versions = (1, 2, 3)

    def testDefaults(self):
        with self.assertRaises(NotImplementedError):
            _eapol = EapolMKA()

    def test_FrameSerialize(self):
        for version in self.versions:
            with self.assertRaises(NotImplementedError):
                _eapol = EapolMKA(version=version)

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


class TestEapolAnnouncementGeneric(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.versions = (1, 2, 3)

    def testDefaults(self):
        with self.assertRaises(NotImplementedError):
            _eapol = EapolAnnouncementGeneric()

    def test_FrameSerialize(self):
        for version in self.versions:
            with self.assertRaises(NotImplementedError):
                _eapol = EapolAnnouncementGeneric(version=version)

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


class TestEapolAnnouncementSpecific(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.versions = (1, 2, 3)

    def testDefaults(self):
        with self.assertRaises(NotImplementedError):
            _eapol = EapolAnnouncementSpecific()

    def test_FrameSerialize(self):
        for version in self.versions:
            with self.assertRaises(NotImplementedError):
                _eapol = EapolAnnouncementSpecific(version=version)

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


class TestEapolAnnouncmentReq(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.versions = (1, 2, 3)

    def testDefaults(self):
        with self.assertRaises(NotImplementedError):
            _eapol = EapolAnnouncmentReq()

    def test_FrameSerialize(self):
        for version in self.versions:
            with self.assertRaises(NotImplementedError):
                _eapol = EapolAnnouncmentReq(version=version)

    def test_FrameDecode(self):
        # TODO: Add test cases
        pass


if __name__ == '__main__':
    unittest.main()
