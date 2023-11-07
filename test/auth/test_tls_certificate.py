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
from cryptography.hazmat.primitives import serialization
from mocks.util import assertGeneratedFrameEquals

from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.tls_certificate import TLSCertificate, ASN_1_Cert, ASN_1_CertList
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType

_cert_1 = "308203cf308202b7a0030201020201" + \
          "02300d06092a864886f70d01010b0500308193310b300906035504061302" + \
          "4652310f300d06035504080c065261646975733112301006035504070c09" + \
          "536f6d65776865726531153013060355040a0c0c4578616d706c6520496e" + \
          "632e3120301e06092a864886f70d010901161161646d696e406578616d70" + \
          "6c652e6f72673126302406035504030c1d4578616d706c65204365727469" + \
          "66696361746520417574686f72697479301e170d32323131303331343237" + \
          "34365a170d3339303430383134323734365a3071310b3009060355040613" + \
          "024652310f300d06035504080c0652616469757331153013060355040a0c" + \
          "0c4578616d706c6520496e632e3119301706035504030c10757365724065" + \
          "78616d706c652e6f7267311f301d06092a864886f70d0109011610757365" + \
          "72406578616d706c652e6f726730820122300d06092a864886f70d010101" + \
          "05000382010f003082010a0282010100a6d467b2e34ee3340985ccb8f7a6" + \
          "0877f274065be896a6ebf8aca1f98136aa3c87733627336ed436322d3b38" + \
          "e041ed55cc14810c80dca08c43416b526898b3d072463b1105ef89b51626" + \
          "cadd324d00e6f8431a218065676fff439e6278e29b3a4eefac6a5c0d688a" + \
          "60404fa1553544a2b47b052e7348b3738f82188cf8413f89487a0be06552" + \
          "5539ae9b640324e5e870e5a620500f4825eee19a5aac99d90181f5fe611a" + \
          "ef4f75350151f5832e02b7186cc42ae8bdbc9fa521f4968dbfd5e365c91f" + \
          "be8a647478068f6feaf196f3db04d280b211eb587ba1ff46f762f4d023db" + \
          "a99fcb26950034506ada3e841ab4a4a381613fc208bdda5a2ce8188d43a9" + \
          "d6650203010001a34f304d30130603551d25040c300a06082b0601050507" + \
          "030230360603551d1f042f302d302ba029a0278625687474703a2f2f7777" + \
          "772e6578616d706c652e636f6d2f6578616d706c655f63612e63726c300d" + \
          "06092a864886f70d01010b0500038201010094b5826d223ff5771e7de9d2" + \
          "d9bcccc83a8102e92c6c7efd36a5d7df5b7d954bd293811b339762bbed9a" + \
          "54e06d6445766681b59451335ee6094f129dca0f82c4774e546d073aca88" + \
          "81d058b205076182259b3f09466faa3177606751a75e3bcf98eb6d334e41" + \
          "a5d8845a48e770298795bd084c95e5dfc197363d69b88126875791042726" + \
          "daf69f1bef875f934da44b89511107dd5c82ecd3e7227e8e688908413f54" + \
          "68da958c3b97aed6a0614e9802e1908dd5fcbb89bc0f0e7493364dc7a875" + \
          "f67b05fb9d0157e54a4f706dad26c23c4bfebf94436223e8b8d5de6f69dd" + \
          "0c5a0fabcb550d2b720c33a03d8013117c163bb2f567a2d03b8c7e57151f" + \
          "6ba60e24"

_cert_2 = "308204fa308203e2a0030201020214118f647a75b8daaa" + \
          "a39dcb62d5f275cc13f2aa70300d06092a864886f70d01010b0500308193" + \
          "310b3009060355040613024652310f300d06035504080c06526164697573" + \
          "3112301006035504070c09536f6d65776865726531153013060355040a0c" + \
          "0c4578616d706c6520496e632e3120301e06092a864886f70d0109011611" + \
          "61646d696e406578616d706c652e6f72673126302406035504030c1d4578" + \
          "616d706c6520436572746966696361746520417574686f72697479301e17" + \
          "0d3232313130333134323635335a170d3339303430383134323635335a30" + \
          "8193310b3009060355040613024652310f300d06035504080c0652616469" + \
          "75733112301006035504070c09536f6d6577686572653115301306035504" + \
          "0a0c0c4578616d706c6520496e632e3120301e06092a864886f70d010901" + \
          "161161646d696e406578616d706c652e6f72673126302406035504030c1d" + \
          "4578616d706c6520436572746966696361746520417574686f7269747930" + \
          "820122300d06092a864886f70d01010105000382010f003082010a028201" + \
          "0100c02381c2ea64ecb02673e5a5b57642c3c9a12ff75de80687d7e4407e" + \
          "c14908b755d2f0ee6220650502abab3aa5c8700a6e916f7e0c1ed50b7a27" + \
          "483196bac678ecdc27427a65780cd1d1b2ce355c114c1162e4505086ec73" + \
          "45ede7601707d6e4373593bacd2299109d2f3c73d99450a88ff64a3274bc" + \
          "3efc2c66bd66d0a2c64d549698868f5194934cf4b25bbc3317cc491ad665" + \
          "893fc24b8b0c34f9ba88b72e143ed02b0a897104d199d77d166311d10927" + \
          "9708120be292133d552f304066c1c182d345fdada0c0ac333759f0076ac6" + \
          "ca14edfe6a3ff3c7aec9d058afa7fc71ae3ae8589c2c9507b6484d435fdb" + \
          "bc34b8a3a4a0fde39d34a5c7514824366fc30203010001a3820142308201" + \
          "3e301d0603551d0e0416041434d3a0b402816618c43419dce5b80d22d41f" + \
          "ed1e3081d30603551d230481cb3081c8801434d3a0b402816618c43419dc" + \
          "e5b80d22d41fed1ea18199a48196308193310b3009060355040613024652" + \
          "310f300d06035504080c065261646975733112301006035504070c09536f" + \
          "6d65776865726531153013060355040a0c0c4578616d706c6520496e632e" + \
          "3120301e06092a864886f70d010901161161646d696e406578616d706c65" + \
          "2e6f72673126302406035504030c1d4578616d706c652043657274696669" + \
          "6361746520417574686f726974798214118f647a75b8daaaa39dcb62d5f2" + \
          "75cc13f2aa70300f0603551d130101ff040530030101ff30360603551d1f" + \
          "042f302d302ba029a0278625687474703a2f2f7777772e6578616d706c65" + \
          "2e6f72672f6578616d706c655f63612e63726c300d06092a864886f70d01" + \
          "010b05000382010100366ccfba4273b3635a9012c3d6b956958d78642b39" + \
          "4dd6924b72a234f7d781130ffcd5e4eea3b25780c7d137311fff5ee78639" + \
          "702d0fbe51bce092b4f23b794f4232421be7f786ba96b5005bcdd0d96ec8" + \
          "a4bff19fc7aad415ea25e3184e7df2cb275f5e63400dfdb199f6db1984b6" + \
          "62edbb9687365f3daceef00af77a2a0052d498fe6ab383465e4bbe10a71e" + \
          "da8a92dc0306396d2836053139b3496204b22ae6ae67b08f13343b0ab7ac" + \
          "00d01004315a07912f1d8a5fb8f142211dc097327e828b5888718e6bca48" + \
          "f594c4dc94c8cdad76cadc3163036aab9394fbf48bed28b41f1027feadcf" + \
          "cf37252ad0426b2998f881b4fd5937e432cbc9fbbad7e86d77"

_test_frame = "0b0008da0008d70003d3" + _cert_1 + "0004fe" + _cert_2
_test_record = "16030108de" + _test_frame


class TestTLSCertificate(unittest.TestCase):
    def setUp(self):
        self.security_params = SecurityParameters()
        self.cert_1 = ASN_1_Cert(bytes.fromhex(_cert_1))
        self.cert_2 = ASN_1_Cert(bytes.fromhex(_cert_2))
        self.cert_list = ASN_1_CertList([self.cert_1, self.cert_2])

    # TODO: Test ASN related objects for this class
    # TODO: What about ITUX509Cert class.  Needed at all?

    def test_FrameSerialize(self):
        cert = TLSCertificate(self.cert_list)
        self.assertEqual(cert.msg_type, TLSHandshakeType.CERTIFICATE)
        expected = _test_frame
        assertGeneratedFrameEquals(self, cert.pack(), expected)

    def test_FrameDecode(self):
        # Construct frame
        frame = _test_frame
        cert = TLSHandshake.parse(bytes.fromhex(frame))

        self.assertIsNotNone(cert)
        self.assertIsInstance(cert, TLSCertificate)
        self.assertEqual(len(cert.certificates), 2)
        cert_1 = cert.certificates[0]
        cert_2 = cert.certificates[1]
        self.assertEqual(cert_1.x509_certificate.public_bytes(serialization.Encoding.DER).hex(), _cert_1)
        self.assertEqual(cert_2.x509_certificate.public_bytes(serialization.Encoding.DER).hex(), _cert_2)

    def test_RecordSerialize(self):
        cert = TLSCertificate(self.cert_list)
        record = cert.to_record()
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        expected = _test_record
        assertGeneratedFrameEquals(self, record.pack(), expected)

    def test_RecordDecode(self):
        # Construct frame
        records = TLSRecord.parse(bytes.fromhex(_test_record), security_params=self.security_params)

        self.assertIsNotNone(records)
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertIsInstance(record, TLSRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        self.assertEqual(len(record.layers), 1)
        cert = record.get_layer("TLSCertificate")
        self.assertIsInstance(cert, TLSCertificate)
        self.assertEqual(len(cert.certificates), 2)
        cert_1 = cert.certificates[0]
        cert_2 = cert.certificates[1]
        self.assertEqual(cert_1.x509_certificate.public_bytes(serialization.Encoding.DER).hex(), _cert_1)
        self.assertEqual(cert_2.x509_certificate.public_bytes(serialization.Encoding.DER).hex(), _cert_2)


if __name__ == '__main__':
    unittest.main()
