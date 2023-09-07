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
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType
from tls_packet.auth.tls_server_hello_done import TLSServerHelloDone


class TestTLSServerHelloDone(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.security_params = SecurityParameters()

    def test_FrameSerialize(self):
        hello = TLSServerHelloDone()
        self.assertEqual(hello.msg_type, TLSHandshakeType.SERVER_HELLO_DONE)
        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            expected = "0e000000"
            assertGeneratedFrameEquals(self, hello.pack(), expected)

    def test_FrameDecode(self):
        # Construct frame
        frame = "0e000000"

        hello = TLSHandshake.parse(bytes.fromhex(frame))

        self.assertIsNotNone(hello)
        self.assertIsInstance(hello, TLSServerHelloDone)

    def test_RecordSerialize(self):
        hello = TLSServerHelloDone()
        record = hello.to_record()
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            expected = "16030100040e000000"
            assertGeneratedFrameEquals(self, record.pack(), expected)

    def test_RecordDecode(self):
        # Construct frame
        record_frame = "16030100040e000000"

        records = TLSRecord.parse(bytes.fromhex(record_frame), self.security_params)

        self.assertIsNotNone(records)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertIsInstance(record, TLSRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        self.assertEqual(len(record.layers), 1)
        hello = record.get_layer("TLSServerHelloDone")
        self.assertIsInstance(hello, TLSServerHelloDone)


if __name__ == '__main__':
    unittest.main()
