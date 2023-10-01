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
from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.tls_record import TLSRecordContentType, TLSRecord, TLSChangeCipherSpecRecord
from tls_packet.packet import DecodeError


class TestTLSRecord(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.security_params = SecurityParameters()

    def test_TLSRecordContentTypes(self):
        # Change underscores to spaces
        valid_codes = {20, 21, 22, 23}
        for code in valid_codes:
            self.assertTrue(TLSRecordContentType.has_value(code))

            name = TLSRecordContentType(code).name()
            self.assertFalse('_' in name)

        for enumeration in (TLSRecordContentType.CHANGE_CIPHER_SPEC,
                            TLSRecordContentType.ALERT,
                            TLSRecordContentType.HANDSHAKE,
                            TLSRecordContentType.APPLICATION_DATA):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = TLSRecordContentType(code)

    def test_TLSRecordDecodeErrors(self):
        with self.assertRaises(DecodeError):
            frame = None
            TLSRecord.parse(frame, security_params=self.security_params)

        with self.assertRaises(DecodeError):    # Empty
            frame = ""
            TLSRecord.parse(bytes.fromhex(frame), security_params=self.security_params)

        with self.assertRaises(DecodeError):    # Truncated
            frame = "1603010001"
            TLSRecord.parse(bytes.fromhex(frame), security_params=self.security_params)

        with self.assertRaises(DecodeError):    # Invalid content type
            frame = "110301000100"
            TLSRecord.parse(bytes.fromhex(frame), security_params=self.security_params)

        with self.assertRaises(DecodeError):    # Bad TLS version
            frame = "160201000100"
            TLSRecord.parse(bytes.fromhex(frame), security_params=self.security_params)

        with self.assertRaises(DecodeError):    # Handshake failed inside the record
            frame = "1602010001FF"
            TLSRecord.parse(bytes.fromhex(frame), security_params=self.security_params)


class TestTLSChangeCipherSpec(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.change_data = "01"
        cls.security_params = SecurityParameters()

    def test_RecordSerialize(self):
        change = TLSChangeCipherSpecRecord(bytes.fromhex(self.change_data))

        with self.assertRaises(NotImplementedError):
            # TODO Add support
            expected = "140301000101"
            assertGeneratedFrameEquals(self, change.pack(), expected)

    def test_RecordDecode(self):
        # Construct frame
        record_frame = "140301000101"

        with self.assertRaises(NotImplementedError):
            # TODO Add support
            records = TLSRecord.parse(bytes.fromhex(record_frame), security_params=self.security_params)

            self.assertIsNotNone(records)
            self.assertIsInstance(records, list)
            self.assertEqual(len(records), 1)

            record = records[0]
            self.assertIsInstance(record, TLSChangeCipherSpecRecord)
            self.assertEqual(record.content_type, TLSRecordContentType.CHANGE_CIPHER_SPEC)
            self.assertEqual(record.data.hex(), self.change_data)


if __name__ == '__main__':
    unittest.main()