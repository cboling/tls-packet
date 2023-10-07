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

from mocks.mock_packet import FIXED_RANDOM
from mocks.util import assertGeneratedFrameEquals
from tls_packet.auth.cipher_suites import CipherSuite
from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.tls import TLSv1
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType
from tls_packet.auth.tls_server_key_exchange import TLSServerKeyExchange, ECCurveType, NamedCurve, TLSServerKeyExchangeECDH


class TestTLSServerKeyExchange(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cipher_suite = CipherSuite.get_from_id(TLSv1(), 0xC014)

        cls.curve_type = ECCurveType.NAMED_CURVE
        cls.named_curve = NamedCurve.SECP256R1
        cls.client_random = "13f856553bbe73787b0acf60bf2a644812804a4fd62328e94984b35299cad491"
        cls.server_random = "391c112416c4dee2aa08c579eb4803f77d9ecfdcb7fe7eb9bf0e9327640d11ca"
        cls.pubkey = "04ceea15247ac22f63d9393d1a160fe67e1962d173a2b75f7fc393fc721467b264d47c1a1915c4f2d29c8d2152b511bfafceb6dddb7ccf9967be094533c1731275"
        cls.signature = ("d378956fca3ba101b8b95189f254f867e4ab5b28a9d1f9481bffdae051a5fea39d036d8b1121719faf3dfa8aa45f755e5c174b5e606778fc27638f99f71cab8" +
                         "6e84b730967897d5f12a3fe152dd06c5569cdb624f0ef3f4a8100e0aa3ebdce6c5395d5823a0b39ba066e5c462e6bc442d01b1c5840943ec0023aedcecde827" +
                         "7651b29beed36ec06495602ce03d68b100ca80217aebe1eae38a6054209980053c50196e5d25cab3f3a53a0ac2738042ea5ed966e00a68da5a3f7300faf39f8" +
                         "9f949df19648220a81eef1e6bb05a588e8138145b4ee84436b534fd011dad694680d7344af86e9a5ca4ad54839487fb09c8a780be055578f79e6f4d73a4aa05939a")
        cls.security_params = SecurityParameters(tls_version=TLSv1(), cipher_suite=cipher_suite,
                                                 client_random=bytes.fromhex(cls.client_random),
                                                 server_random=bytes.fromhex(cls.server_random))

    def test_ECCurveType(self):
        # Change underscores to spaces
        valid_codes = {1, 2, 3}
        for code in valid_codes:
            self.assertTrue(ECCurveType.has_value(code))

            name = ECCurveType(code).name()
            self.assertFalse('_' in name)

        for enumeration in (ECCurveType.EXPLICIT_PRIME,
                            ECCurveType.EXPLICIT_CHAR2,
                            ECCurveType.NAMED_CURVE):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = ECCurveType(code)

    def test_NamedCurve(self):
        # Change underscores to spaces
        valid_codes = {23, 24, 25, 29, 30}
        for code in valid_codes:
            self.assertTrue(NamedCurve.has_value(code))

            name = NamedCurve(code).name()
            self.assertFalse('_' in name)

        for enumeration in (NamedCurve.SECP256R1,
                            NamedCurve.SECP384R1,
                            NamedCurve.SECP521R1,
                            NamedCurve.X25519,
                            NamedCurve.X488):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = NamedCurve(code)

    def test_FrameSerialize(self):
        skey = TLSServerKeyExchange(self.curve_type, self.named_curve,
                                    bytes.fromhex(self.pubkey),
                                    bytes.fromhex(self.signature))
        self.assertEqual(skey.msg_type, TLSHandshakeType.SERVER_KEY_EXCHANGE)
        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            expected = "0c0001470300174104ceea15247ac22f63d9393d1a160fe67e1962d173a2b75f7fc393fc721467b264d47c1a1915c4f2d29c8d2152b511bfafceb6dddb7ccf9967be094533c17312750100d378956fca3ba101b8b95189f254f867e4ab5b28a9d1f9481bffdae051a5fea39d036d8b1121719faf3dfa8aa45f755e5c174b5e606778fc27638f99f71cab86e84b730967897d5f12a3fe152dd06c5569cdb624f0ef3f4a8100e0aa3ebdce6c5395d5823a0b39ba066e5c462e6bc442d01b1c5840943ec0023aedcecde8277651b29beed36ec06495602ce03d68b100ca80217aebe1eae38a6054209980053c50196e5d25cab3f3a53a0ac2738042ea5ed966e00a68da5a3f7300faf39f89f949df19648220a81eef1e6bb05a588e8138145b4ee84436b534fd011dad694680d7344af86e9a5ca4ad54839487fb09c8a780be055578f79e6f4d73a4aa05939a"
            assertGeneratedFrameEquals(self, skey.pack(), expected)

    def test_FrameDecode(self):
        # Construct frame
        frame = "0c0001470300174104ceea15247ac22f63d9393d1a160fe67e1962d173a2b75f7fc393fc721467b264d47c1a1915c4f2d29c8d2152b511bfafceb6dddb7ccf9967be094533c17312750100d378956fca3ba101b8b95189f254f867e4ab5b28a9d1f9481bffdae051a5fea39d036d8b1121719faf3dfa8aa45f755e5c174b5e606778fc27638f99f71cab86e84b730967897d5f12a3fe152dd06c5569cdb624f0ef3f4a8100e0aa3ebdce6c5395d5823a0b39ba066e5c462e6bc442d01b1c5840943ec0023aedcecde8277651b29beed36ec06495602ce03d68b100ca80217aebe1eae38a6054209980053c50196e5d25cab3f3a53a0ac2738042ea5ed966e00a68da5a3f7300faf39f89f949df19648220a81eef1e6bb05a588e8138145b4ee84436b534fd011dad694680d7344af86e9a5ca4ad54839487fb09c8a780be055578f79e6f4d73a4aa05939a"

        skey = TLSHandshake.parse(bytes.fromhex(frame), security_params=self.security_params, verify_contents=True)

        self.assertIsNotNone(skey)
        self.assertIsInstance(skey, TLSServerKeyExchange)
        self.assertEqual(skey.curve_type, self.curve_type)
        self.assertEqual(skey.named_curve, self.named_curve)
        self.assertEqual(skey.key.hex(), self.pubkey)
        self.assertEqual(skey.signature.hex(), self.signature)

    def test_RecordSerialize(self):
        skey = TLSServerKeyExchange(self.curve_type, self.named_curve,
                                    bytes.fromhex(self.pubkey),
                                    bytes.fromhex(self.signature))
        record = skey.to_record()
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            expected = "160301014b0c0001470300174104ceea15247ac22f63d9393d1a160fe67e1962d173a2b75f7fc393fc721467b264d47c1a1915c4f2d29c8d2152b511bfafceb6dddb7ccf9967be094533c17312750100d378956fca3ba101b8b95189f254f867e4ab5b28a9d1f9481bffdae051a5fea39d036d8b1121719faf3dfa8aa45f755e5c174b5e606778fc27638f99f71cab86e84b730967897d5f12a3fe152dd06c5569cdb624f0ef3f4a8100e0aa3ebdce6c5395d5823a0b39ba066e5c462e6bc442d01b1c5840943ec0023aedcecde8277651b29beed36ec06495602ce03d68b100ca80217aebe1eae38a6054209980053c50196e5d25cab3f3a53a0ac2738042ea5ed966e00a68da5a3f7300faf39f89f949df19648220a81eef1e6bb05a588e8138145b4ee84436b534fd011dad694680d7344af86e9a5ca4ad54839487fb09c8a780be055578f79e6f4d73a4aa05939a"
            assertGeneratedFrameEquals(self, record.pack(), expected)

    def test_RecordDecode(self):
        # Construct frame
        record_frame = "160301014b0c0001470300174104ceea15247ac22f63d9393d1a160fe67e1962d173a2b75f7fc393fc721467b264d47c1a1915c4f2d29c8d2152b511bfafceb6dddb7ccf9967be094533c17312750100d378956fca3ba101b8b95189f254f867e4ab5b28a9d1f9481bffdae051a5fea39d036d8b1121719faf3dfa8aa45f755e5c174b5e606778fc27638f99f71cab86e84b730967897d5f12a3fe152dd06c5569cdb624f0ef3f4a8100e0aa3ebdce6c5395d5823a0b39ba066e5c462e6bc442d01b1c5840943ec0023aedcecde8277651b29beed36ec06495602ce03d68b100ca80217aebe1eae38a6054209980053c50196e5d25cab3f3a53a0ac2738042ea5ed966e00a68da5a3f7300faf39f89f949df19648220a81eef1e6bb05a588e8138145b4ee84436b534fd011dad694680d7344af86e9a5ca4ad54839487fb09c8a780be055578f79e6f4d73a4aa05939a"

        records = TLSRecord.parse(bytes.fromhex(record_frame), security_params=self.security_params,
                                  verify_contents=True)

        self.assertIsNotNone(records)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertIsInstance(record, TLSRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        self.assertEqual(len(record.layers), 1)

        skey = record.get_layer("TLSServerKeyExchangeECDH")
        self.assertIsInstance(skey, TLSServerKeyExchangeECDH)

        self.assertEqual(skey.curve_type, self.curve_type)
        self.assertEqual(skey.named_curve, self.named_curve)
        self.assertEqual(skey.key.hex(), self.pubkey)
        self.assertEqual(skey.signature.hex(), self.signature)


if __name__ == '__main__':
    unittest.main()
