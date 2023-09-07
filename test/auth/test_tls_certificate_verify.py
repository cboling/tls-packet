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
from tls_packet.auth.tls_certificate_verify import TLSCertificateVerify
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType

_signature = "896d575fc15141266a4fc7f7c3943139025bbca56a8b2ac5db7836bbaa4245c6e6b1f151466054fdb195ba000db1d0abc1cac2ee39fb7d3a74556b39c31fb2fc8a5eb99db259cb49490e79b05afe904f26a117ae14ba82e25c85270b25fce7c324ac805ede347084f5d4ac5902b98f7e313abaeceea5a0d1bcb3d2cecbe98e182c8821c2716cf4781529f3ed8ea3c775f773dc548b3be49547dd1e7e005567ac4e5e42dd9759db7103ad8890c19b9d86a0995ac8b4869fa4a7975794483aed5b7edb59457efe90be41c63790832a776775fe63b105505167d2aba536f9ed15a57b520dabe2019b2daa1d32c5ea694130dd9f6fbd75cb13f7e6248f21331d48fa"
_frame = "0f0001020100" + _signature


class TestTLSCertificateVerify(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.signature = _signature
        cls.security_params = SecurityParameters()

    def test_FrameSerialize(self):
        sig = TLSCertificateVerify(signature=bytes.fromhex(self.signature))
        self.assertEqual(sig.msg_type, TLSHandshakeType.CERTIFICATE_VERIFY)

        expected = _frame
        assertGeneratedFrameEquals(self, sig.pack(), expected)

    def test_FrameDecode(self):
        # Construct frame
        frame = _frame

        sig = TLSHandshake.parse(bytes.fromhex(frame))

        self.assertIsNotNone(sig)
        self.assertIsInstance(sig, TLSCertificateVerify)
        self.assertEqual(sig.signature.hex(), self.signature)

    def test_RecordSerialize(self):
        sig = TLSCertificateVerify(signature=bytes.fromhex(self.signature))
        record = sig.to_record()
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        expected = "1603010106" + _frame
        assertGeneratedFrameEquals(self, record.pack(), expected)

    def test_RecordDecode(self):
        # Construct frame
        record_frame = "1603010106" + _frame

        records = TLSRecord.parse(bytes.fromhex(record_frame), self.security_params)

        self.assertIsNotNone(records)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertIsInstance(record, TLSRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        self.assertEqual(len(record.layers), 1)
        sig = record.get_layer("TLSCertificateVerify")
        self.assertIsInstance(sig, TLSCertificateVerify)
        self.assertEqual(sig.signature.hex(), self.signature)


if __name__ == '__main__':
    unittest.main()
