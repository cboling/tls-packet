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

import os
import unittest
from mocks.util import assertGeneratedFrameEquals

from tls_packet.auth.cipher_suites import CipherSuite
from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.tls import TLSv1_2
from tls_packet.auth.tls_certificate import ASN_1_Cert
from tls_packet.auth.tls_client import TLSClient
from tls_packet.auth.tls_client_key_exchange import TLSClientKeyExchange, TLSClientKeyEncoding
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_record import TLSRecord, TLSHandshakeRecord, TLSRecordContentType

_rsa_key = "010086962490be27f16293a3a3f21eda3d838e9c5695c26aa3be94def7c3662ffbf71eeb2bcb922ebe5f71ea95eef6a9219315390e2765c8dfe3fedc320e9a76ddca1ed4877adfbcdb677f4aa055f29b8d96c26a666218bbb7731fe93ffd8dc85d69e5dde130339c48fa6e96fb78ffcdb70cd5bdf0d9b15e581d6c7de572bfe9587e65c7e6e860d5e9f7de6a7d2b11b180bfe8bbc16bbbcf7e350c895c5eef686b32c8fc0f78c27dd41ed9e8dc187110c747a651e23a3ed640be5af54b018affecd0e49705d575a0b319190c6645e806be4366bf8009cfef4e03f927d34b64dfed51a7bbb61f3a06034e765f608b423bd6b9e63cb27d381400957bf0ffaf89a9274b"


class TestTLSClientKeyExchange(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.rsa_key = bytes.fromhex(_rsa_key)
        cls.rsa_random = os.urandom(46)
        cls.encoding = TLSClientKeyEncoding.RSA_PREMASTER_SECRET

        client_random = "66339322759161ea77991987a8651443d0598de26a5107cb96439d35f26aeefb"
        server_random = "366ac968420ba8630ea0b09bd9479799963ef8bd871d9633563b9a229ac6329f"

        cipher_suite = CipherSuite.get_from_id(TLSv1_2(), 0x002f)
        server_certificate = "00058a308205863082046ea003020102021002d6dd101517a77f028456ad948f2b29300d06092a864886f70d01010505003058310b300906035504061302555331193017060355040a131041545420536572766963657320496e63312e302c06035504030c2541545420536572766963657320496e6320456e68616e636564205365727669636573204341301e170d3233303232323030303030305a170d3234303232323233353935395a308191310b3009060355040613025553310e300c060355040813055465786173310f300d0603550407130644616c6c6173311c301a060355040a0c13415426542053657276696365732c20496e632e31163014060355040b130d706c616e747868736161613031312b302906035504031322706c616e7478687361616130312e6f70732e6532652e6c6162732e6174742e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100eef2b77ef8c4d0139e7b93aed73afe57a4969ede04ad5c698533d62b5616b8a0e483b7223598ac6ea22db545d10d67f8afb66603562630e7eaa545efec8d9d367f24b08db2931deabd3adf44dc2ed89a25de48da48ed1b3f37997d2aa57a2ace092451453c23e57a522319089aef980b07c5b9e23e9e11252d128edec6a13362e93523cd4b078d8aee2b00b1101d79422c4ce33d6ec939779983f3c655dffa0d601c0953571d53f00db1472393b6c6787db9cc1f3a4b4f29dd16f493f0659d252cf726ad5d4a6fcd2d99362ec18d567c28c1815cf6d4e04f9f723d6c1ad18a603a4ebfa3a50bb062ace11c35ab9061032e9adc7584c2c14b19083476ef91b2eb0203010001a38202103082020c301f0603551d23041830168014eddf4ab06489360cac4b92cc948632b8978141a8301d0603551d0e04160414236379537d825103a07f2dec15cea13bec1dc3a7302d0603551d11042630248222706c616e7478687361616130312e6f70732e6532652e6c6162732e6174742e636f6d300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b060105050703023081950603551d1f04818d30818a3043a041a03f863d687474703a2f2f63726c332e64696769636572742e636f6d2f4154545365727669636573496e63456e68616e636564536572766963657343412e63726c3043a041a03f863d687474703a2f2f63726c342e64696769636572742e636f6d2f4154545365727669636573496e63456e68616e636564536572766963657343412e63726c30410603551d20043a3038303606096086480186fd6c01013029302706082b06010505070201161b687474703a2f2f7777772e64696769636572742e636f6d2f43505330818206082b0601050507010104763074302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304c06082b060105050730028640687474703a2f2f636163657274732e64696769636572742e636f6d2f4154545365727669636573496e63456e68616e636564536572766963657343412e637274300c0603551d130101ff04023000300d06092a864886f70d0101050500038201010018701f322689a0def9b2d8a33c037a52e6fa3f3fddf25ddd0fd32c39f627e8e2dec29700f63f90667c0093cd634fbd1db012abe79f395e617838fc31e8c7b31f74902fcf1827ab62fbe89b6519428484f08ea98a50fabba7d2c70abbb57efb3c374ce79ae8fb57b505cea6b5350d7c9a67f3dc61fdf6aeff479519799b92da3837cca2d71e9e6e94539663c4521c25a4a5cf0085ffca9867b39d7bd3d88db99abeaa6e8176586838ab09d979c7d497daaaa5467de082da787c1af2abdab6785fff384af93cc80ca71babd549bbd52c580cd8e63ca0eaa6f304af4fc11d547b9b04487347376d1e6baecccd473ab4504a15b53e9f3159488e8dfbd5dc001dae80"
        server_cert_bytes = bytes.fromhex(server_certificate)
        asn_cert = ASN_1_Cert.parse(server_cert_bytes)
        server_cert = asn_cert.x509_certificate

        # The version number in the PreMasterSecret is the version offered by the client
        # in the ClientHello.client_version, not the version negotiated for the connection
        security_params = SecurityParameters(cipher_suite=cipher_suite,
                                             client_random=bytes.fromhex(client_random),
                                             server_random=bytes.fromhex(server_random),
                                             server_certificate=server_cert)

        tls_client = TLSClient(None,
                               tls_version=TLSv1_2(),
                               random_data=bytes.fromhex(client_random))

        rx_params = tls_client.rx_security_parameters(active=False)
        tx_params = tls_client.tx_security_parameters(active=False)
        rx_params.cipher_suite = tx_params.cipher_suite = cipher_suite
        rx_params.server_random = tx_params.server_random = bytes.fromhex(server_random)
        rx_params.server_certificate = tx_params.server_certificate = server_cert

        cls.security_params = security_params
        cls.tls_client = tls_client


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

    def test_FrameSerializeCanned(self):
        """ Test just the wrapping of a key already computed"""
        ckey = TLSClientKeyExchange(key=self.rsa_key)
        self.assertEqual(ckey.msg_type, TLSHandshakeType.CLIENT_KEY_EXCHANGE)
        expected = "10000102" + _rsa_key
        assertGeneratedFrameEquals(self, ckey.pack(), expected)

    def test_FrameSerializeRSA(self):
        """ Test creating a new key """
        ckey = TLSClientKeyExchange.create(self.tls_client, random=self.rsa_random)

        self.assertEqual(ckey.msg_type, TLSHandshakeType.CLIENT_KEY_EXCHANGE)

        # The RSA Client key contains a random number so we cannot compare it to anything pre-computed
        # TODO: If we create the server certificate used, then we could use the server's private key
        #       to decrypt the pre-master secret and see if we can reverse engineer the random number
        #       and do that comparison

    def test_FrameDecode(self):
        # Construct frame
        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            frame = "10000102" + _rsa_key
            ckey = TLSHandshake.parse(bytes.fromhex(frame))

            self.assertIsNotNone(ckey)
            self.assertIsInstance(ckey, TLSClientKeyExchange)
            self.assertEqual(ckey.key, self.rsa_key)
            self.assertEqual(ckey.encoding, self.encoding)

    def test_RecordSerializeCanned(self):
        ckey = TLSClientKeyExchange(key=self.rsa_key)
        record = ckey.to_record()
        self.assertIsInstance(record, TLSHandshakeRecord)
        self.assertEqual(record.content_type, TLSRecordContentType.HANDSHAKE)

        expected = "160301010610000102" + _rsa_key
        assertGeneratedFrameEquals(self, record.pack(), expected)

    def test_RecordDecode(self):
        # Construct frame
        record_frame = "160301010610000102" + _rsa_key

        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            records = TLSRecord.parse(bytes.fromhex(record_frame), security_params=self.security_params)

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
