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
from tls_packet.auth.tls_certificate_request import TLSCertificateRequest, CertificateType
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType


class TestTLSCertificateRequest(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.security_params = SecurityParameters()
        cls.dsn_empty = b""
        cls.cert_types = (
            CertificateType.RSA_SIGN,
            CertificateType.DSS_SIGN,
            CertificateType.ECDSA_SIGN)

    def test_FrameSerialize(self):
        req = TLSCertificateRequest(self.cert_types, self.dsn_empty)
        self.assertEqual(req.msg_type, TLSHandshakeType.CERTIFICATE_REQUEST)

        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            expected = "0d000006030102400000"
            assertGeneratedFrameEquals(self, req.pack(), expected)

    def test_FrameDecode(self):
        # Construct frame
        frame = "0d000006030102400000"

        hello = TLSHandshake.parse(bytes.fromhex(frame))

        self.assertIsNotNone(hello)
        self.assertIsInstance(hello, TLSCertificateRequest)
        self.assertEqual(hello.certificate_types, self.cert_types)
        self.assertEqual(hello.dsn, self.dsn_empty)
        # TODO: test non-empty DSN as well

    def test_RecordSerialize(self):
        hello = TLSCertificateRequest(self.cert_types, self.dsn_empty)
        record = hello.to_record()
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            expected = "160301000a0d000006030102400000"
            assertGeneratedFrameEquals(self, record.pack(), expected)

    def test_RecordDecode(self):
        # Construct frame
        record_frame = "160301000a0d000006030102400000"

        records = TLSRecord.parse(bytes.fromhex(record_frame), security_params=self.security_params)

        self.assertIsNotNone(records)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertIsInstance(record, TLSRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        self.assertEqual(len(record.layers), 1)
        req = record.get_layer("TLSCertificateRequest")
        self.assertIsInstance(req, TLSCertificateRequest)
        self.assertEqual(req.certificate_types, self.cert_types)
        self.assertEqual(req.dsn, self.dsn_empty)


if __name__ == '__main__':
    unittest.main()
