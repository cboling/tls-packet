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
from tls_packet.auth.tls_client_key_exchange import TLSClientKeyExchange, TLSClientKeyEncoding
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType

_key = "4104c9a7ea8e286607e14faad6307ed94fcaac608a0cde8238c72dddb210dd96d5907a2c8d522c43fb3bc9b030050a82b66397eb6edd904cf0444e411e8e0b969c24"


class TestTLSClientKeyExchange(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.key = bytes.fromhex(_key)
        cls.encoding = TLSClientKeyEncoding.UNKNOWN
        cls.security_params = SecurityParameters()

    def test_TLSClientKeyEncoding(self):
        # Change underscores to spaces
        valid_codes = {0, 1, 2}
        for code in valid_codes:
            self.assertTrue(TLSClientKeyEncoding.has_value(code))

            name = TLSClientKeyEncoding(code).name()
            self.assertFalse('_' in name)

        for enumeration in (TLSClientKeyEncoding.UNKNOWN,
                            TLSClientKeyEncoding.RSA_PREMASTER_SECRET,
                            TLSClientKeyEncoding.CLIENT_DIFFIE_HELLMAN_PUBLIC):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = TLSClientKeyEncoding(code)

    def test_FrameSerialize(self):
        ckey = TLSClientKeyExchange(key=self.key)
        self.assertEqual(ckey.msg_type, TLSHandshakeType.CLIENT_KEY_EXCHANGE)
        expected = "10000042" + _key
        assertGeneratedFrameEquals(self, ckey.pack(), expected)
        # TODO: Add test cases for RSA and DiffieHellman key encoding

    def test_FrameDecode(self):
        # Construct frame
        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            frame = "10000042" + _key
            ckey = TLSHandshake.parse(bytes.fromhex(frame))

            self.assertIsNotNone(ckey)
            self.assertIsInstance(ckey, TLSClientKeyExchange)
            self.assertEqual(ckey.key, self.key)
            self.assertEqual(ckey.encoding, self.encoding)

    def test_RecordSerialize(self):
        ckey = TLSClientKeyExchange(key=self.key)
        record = ckey.to_record()
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        expected = "160301004610000042" + _key
        assertGeneratedFrameEquals(self, record.pack(), expected)

    def test_RecordDecode(self):
        # Construct frame
        record_frame = "160301004610000042" + _key

        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            records = TLSRecord.parse(bytes.fromhex(record_frame), self.security_params)

            self.assertIsNotNone(records)
            self.assertIsInstance(records, list)
            self.assertEqual(len(records), 1)

            record = records[0]
            self.assertIsInstance(record, TLSRecord)
            self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

            self.assertEqual(len(record.layers), 1)
            ckey = record.get_layer("TLSClientKeyExchange")
            self.assertIsInstance(ckey, TLSClientKeyExchange)


if __name__ == '__main__':
    unittest.main()
