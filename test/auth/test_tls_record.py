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

from tls_packet.packet import DecodeError
from tls_packet.auth.tls_record import TLSRecordContentType, TLSRecord
from tls_packet.auth.security_params import SecurityParameters


class TestTLSRecord(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.security_params = SecurityParameters()

    def test_TLSRecordContentTypes(self):
        # Change underscores to spaces
        for code in (20, 21, 22, 23):
            self.assertTrue(TLSRecordContentType.has_value(code))

            name = TLSRecordContentType(code).name()
            self.assertFalse('_' in name)

        for enumeration in (TLSRecordContentType.CHANGE_CIPHER_SPEC,
                            TLSRecordContentType.ALERT,
                            TLSRecordContentType.HANDSHAKE,
                            TLSRecordContentType.APPLICATION_DATA):
            self.assertTrue(0 <= enumeration.value <= 255)

    def test_TLSRecordDecodeErrors(self):
        with self.assertRaises(DecodeError):
            frame = None
            TLSRecord.parse(frame, self.security_params)

        with self.assertRaises(DecodeError):    # Empty
            frame = ""
            TLSRecord.parse(bytes.fromhex(frame), self.security_params)

        with self.assertRaises(DecodeError):    # Truncated
            frame = "1603010001"
            TLSRecord.parse(bytes.fromhex(frame), self.security_params)

        with self.assertRaises(DecodeError):    # Invalid content type
            frame = "110301000100"
            TLSRecord.parse(bytes.fromhex(frame), self.security_params)

        with self.assertRaises(DecodeError):    # Bad TLS version
            frame = "160201000100"
            TLSRecord.parse(bytes.fromhex(frame), self.security_params)

        with self.assertRaises(DecodeError):    # Handshake failed inside the record
            frame = "1602010001FF"
            TLSRecord.parse(bytes.fromhex(frame), self.security_params)


if __name__ == '__main__':
    unittest.main()