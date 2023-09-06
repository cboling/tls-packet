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
from tls_packet.packet import DecodeError
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_hello import TLSHelloRequest
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType
from tls_packet.auth.security_params import SecurityParameters


class TestTLSHello(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.security_params = SecurityParameters()

    def test_TLSHelloFrameSerialize(self):
        expected = "00"
        hello = TLSHelloRequest()
        assertGeneratedFrameEquals(self, hello.pack(), expected)
        self.assertEqual(hello.msg_type, TLSHandshakeType.HELLO_REQUEST)

    def test_TLSHelloFrameDecode(self):
        # Construct frame
        hello_frame = "00"

        hello = TLSHandshake.parse(bytes.fromhex(hello_frame))

        self.assertIsNotNone(hello)
        self.assertIsInstance(hello, TLSHelloRequest)

    def test_TLSHelloRecordSerialize(self):
        hello = TLSHelloRequest()
        record = hello.to_record()
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        expected = "160301000100"
        assertGeneratedFrameEquals(self, record.pack(), expected)

    def test_TLSHelloRecordDecode(self):
        # Construct frame
        record_frame = "160301000100"

        records = TLSRecord.parse(bytes.fromhex(record_frame), self.security_params)

        self.assertIsNotNone(records)
        import sys
        print(f"RECORD: {repr(records)}", sys.stderr)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)
        self.assertEqual(record.length, 1)

        layer = record.get_layer("TLSHelloRequest")
        self.assertIsNotNone(layer)
        self.assertEqual(layer.msg_type, TLSHandshakeType.HELLO_REQUEST)


if __name__ == '__main__':
    unittest.main()