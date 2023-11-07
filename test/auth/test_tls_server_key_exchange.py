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

from tls_packet.auth.cipher_suites import CipherSuite
from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.tls import TLSv1
from tls_packet.auth.tls_certificate import ASN_1_Cert
from tls_packet.auth.tls_client import TLSClient
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_named_curve import ECCurveType, NamedCurveType
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType
from tls_packet.auth.tls_server_key_exchange import TLSServerKeyExchange, TLSServerKeyExchangeECDH


class TestTLSServerKeyExchangeECDH(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cipher_suite = CipherSuite.get_from_id(TLSv1(), 0xC014)
        cls.curve_type = ECCurveType.NAMED_CURVE
        cls.named_curve_type = NamedCurveType.SECP256R1

        client_random = "13f856553bbe73787b0acf60bf2a644812804a4fd62328e94984b35299cad491"
        server_random = "391c112416c4dee2aa08c579eb4803f77d9ecfdcb7fe7eb9bf0e9327640d11ca"
        cls.pubkey = "04ceea15247ac22f63d9393d1a160fe67e1962d173a2b75f7fc393fc721467b264d47c1a1915c4f2d29c8d2152b511bfafceb6dddb7ccf9967be094533c1731275"
        cls.signature = ("d378956fca3ba101b8b95189f254f867e4ab5b28a9d1f9481bffdae051a5fea39d036d8b1121719faf3dfa8aa45f755e5c174b5e606778fc27638f99f71cab8" +
                         "6e84b730967897d5f12a3fe152dd06c5569cdb624f0ef3f4a8100e0aa3ebdce6c5395d5823a0b39ba066e5c462e6bc442d01b1c5840943ec0023aedcecde827" +
                         "7651b29beed36ec06495602ce03d68b100ca80217aebe1eae38a6054209980053c50196e5d25cab3f3a53a0ac2738042ea5ed966e00a68da5a3f7300faf39f8" +
                         "9f949df19648220a81eef1e6bb05a588e8138145b4ee84436b534fd011dad694680d7344af86e9a5ca4ad54839487fb09c8a780be055578f79e6f4d73a4aa05939a")

        server_certificate = "0003de308203da308202c2a003020102020101300d06092a864886f70d01010b0500308193310b3009060355040613024652310f300d06035504080c065261646975733112301006035504070c09536f6d65776865726531153013060355040a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901161161646d696e406578616d706c652e6f72673126302406035504030c1d4578616d706c6520436572746966696361746520417574686f72697479301e170d3232313130333134323730375a170d3339303430383134323730375a307c310b3009060355040613024652310f300d06035504080c0652616469757331153013060355040a0c0c4578616d706c6520496e632e3123302106035504030c1a4578616d706c65205365727665722043657274696669636174653120301e06092a864886f70d010901161161646d696e406578616d706c652e6f726730820122300d06092a864886f70d01010105000382010f003082010a0282010100d9a320bb37e6c9abd67159680b86f036a108a3eb5b91165731794bb4fdd2f4869b67e530cf5dbaf8289fa1e20fc81a87a58138880253379284738ec5584b4ecfa97178141a22eddf76ea7385e08d1f186a550b9db767354cd3fd38d9879469bc02dc28fa83515453b51f60f2232319bf081d115d661f3794f33bf0bab1df292c9808e8f1c59010b8a6a15617c5952304ea85fb66c1936e3e9059ac5fd67fbe7d638c1e5b7ba57f716189607ea6d6ccfe0fda33e15905bf46e4f4100d56a40f7ca532e42e8d4da450cc190fbb874013b4093f446aba990ff005228bd1973af93b0f08ea0ca638c9574f1a73bf5b89bf4c8ac0745b3c07bef2a5e9f82d47c281dd0203010001a34f304d30130603551d25040c300a06082b0601050507030130360603551d1f042f302d302ba029a0278625687474703a2f2f7777772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d06092a864886f70d01010b05000382010100291f97deb51c0afa81fd42f9de3c45ea2947d80c2ae73860cd74596f8324f94484bbd3f99dae8a6139af67d8df24a9d099642720e77afabfb5c271013b57dc64266ee11e89286942bf95f7c80c043a3424468790fb92a932fe773e5627f5f12799cfe9ee16b7946ca47384ed2e12afb001e3d0dee7e694810177de9c507a3db9b2835891a5afac3381fe64e054e717f23421996d9888233cc6598474bac98eda31bde594641f60ff332dc48cb351188313cfc1905a68347e28e8cf294817ab764a4f4a6deb02bab584ea298e7a444d7f3b35e2084f82c944f5d1a597709362e7cb5e6da8e57f2acc14cfad512f1f916381268928448047c47b945431232b262c"
        asn_cert = ASN_1_Cert.parse(bytes.fromhex(server_certificate))
        server_cert = asn_cert.x509_certificate

        security_params = SecurityParameters(cipher_suite=cipher_suite,
                                             client_random=bytes.fromhex(client_random),
                                             server_random=bytes.fromhex(server_random),
                                             server_certificate=server_cert)

        tls_client = TLSClient(None,
                               tls_version=TLSv1(),
                               random_data=bytes.fromhex(client_random))

        rx_params = tls_client.rx_security_parameters(active=False)
        tx_params = tls_client.tx_security_parameters(active=False)
        rx_params.cipher_suite = tx_params.cipher_suite = cipher_suite
        rx_params.server_random = tx_params.server_random = bytes.fromhex(server_random)
        rx_params.server_certificate = tx_params.server_certificate = server_cert

        cls.security_params = security_params
        cls.tls_client = tls_client

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

    def test_NamedCurveType(self):
        # Change underscores to spaces
        valid_codes = {23, 24, 25, 29, 30}
        for code in valid_codes:
            self.assertTrue(NamedCurveType.has_value(code))

            name = NamedCurveType(code).name()
            self.assertFalse('_' in name)

        for enumeration in (NamedCurveType.SECP256R1,
                            NamedCurveType.SECP384R1,
                            NamedCurveType.SECP521R1,
                            NamedCurveType.X25519,
                            NamedCurveType.X488):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = NamedCurveType(code)

    def test_FrameSerialize(self):
        skey = TLSServerKeyExchangeECDH(self.curve_type, self.named_curve_type,
                                        bytes.fromhex(self.pubkey),
                                        bytes.fromhex(self.signature), security_params=self.security_params)
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
        self.assertIsInstance(skey, TLSServerKeyExchangeECDH)
        self.assertEqual(skey.curve_type, self.curve_type)
        self.assertEqual(skey.named_curve_type, self.named_curve_type)
        self.assertEqual(skey.key.hex(), self.pubkey)
        self.assertEqual(skey.signature.hex(), self.signature)

    def test_RecordSerialize(self):
        skey = TLSServerKeyExchangeECDH(self.curve_type, self.named_curve_type,
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
        self.assertIsInstance(skey, TLSServerKeyExchange)
        self.assertIsInstance(skey, TLSServerKeyExchangeECDH)

        self.assertEqual(skey.curve_type, self.curve_type)
        self.assertEqual(skey.named_curve_type, self.named_curve_type)
        self.assertEqual(skey.key.hex(), self.pubkey)
        self.assertEqual(skey.signature.hex(), self.signature)

        algorithm = self.security_params.cipher_suite.signature_algorithm(self.security_params,
                                                                          self.tls_client.tls_version)
        valid = algorithm.verify(skey.signature, skey.server_params)

        self.assertTrue(valid)


if __name__ == '__main__':
    unittest.main()
