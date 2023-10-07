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

from tls_packet.auth.tls_extension import TLSHelloExtensionType


class TestTLSExtension(unittest.TestCase):
    @classmethod
    def setUp(cls):
        # cls.security_params = SecurityParameters()
        pass

    def test_TLSHelloExtensionType(self):
        # Change underscores to spaces
        valid_codes = {x for x in range(0, 61) if x not in (40, 46)} | {0xff01}
        for code in valid_codes:
            self.assertTrue(TLSHelloExtensionType.has_value(code))

            name = TLSHelloExtensionType(code).name()
            self.assertFalse('_' in name)

        for enumeration in (TLSHelloExtensionType.SERVER_NAME,
                            TLSHelloExtensionType.MAX_FRAGMENT_LENGTH,
                            TLSHelloExtensionType.CLIENT_CERTIFICATE_URL,
                            TLSHelloExtensionType.TRUSTED_CA_KEYS,
                            TLSHelloExtensionType.TRUNCATED_HMAC,
                            TLSHelloExtensionType.STATUS_REQUEST,
                            TLSHelloExtensionType.USER_MAPPING,
                            TLSHelloExtensionType.CLIENT_AUTHZ,
                            TLSHelloExtensionType.SERVER_AUTHZ,
                            TLSHelloExtensionType.CERT_TYPE,
                            TLSHelloExtensionType.SUPPORTED_GROUPS,
                            TLSHelloExtensionType.EC_POINT_FORMATS,
                            TLSHelloExtensionType.SRP,
                            TLSHelloExtensionType.SIGNATURE_ALGORITHMS,
                            TLSHelloExtensionType.USE_SRTP,
                            TLSHelloExtensionType.HEARTBEAT,
                            TLSHelloExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                            TLSHelloExtensionType.STATUS_REQUEST_V2,
                            TLSHelloExtensionType.SIGNED_CERTIFICATE_TIMESTAMP,
                            TLSHelloExtensionType.CLIENT_CERTIFICATE_TYPE,
                            TLSHelloExtensionType.SERVER_CERTIFICATE_TYPE,
                            TLSHelloExtensionType.PADDING,
                            TLSHelloExtensionType.ENCRYPT_THEN_MAC,
                            TLSHelloExtensionType.EXTENDED_MASTER_SECRET,
                            TLSHelloExtensionType.TOKEN_BINDING,
                            TLSHelloExtensionType.CACHED_INFO,
                            TLSHelloExtensionType.TLS_LTS,
                            TLSHelloExtensionType.COMPRESS_CERTIFICATE,
                            TLSHelloExtensionType.RECORD_SIZE_LIMIT,
                            TLSHelloExtensionType.PWD_PROTECT,
                            TLSHelloExtensionType.PWD_CLEAR,
                            TLSHelloExtensionType.PASSWORD_SALT,
                            TLSHelloExtensionType.TICKET_PINNING,
                            TLSHelloExtensionType.TLS_CERT_WITH_EXTERN_PSK,
                            TLSHelloExtensionType.DELEGATED_CREDENTIAL,
                            TLSHelloExtensionType.SESSION_TICKET,
                            TLSHelloExtensionType.TLMSP,
                            TLSHelloExtensionType.TLMSP_PROXYING,
                            TLSHelloExtensionType.TLMSP_DELEGATE,
                            TLSHelloExtensionType.SUPPORTED_EKT_CIPHERS,
                            TLSHelloExtensionType.PRE_SHARED_KEY,
                            TLSHelloExtensionType.EARLY_DATA,
                            TLSHelloExtensionType.SUPPORTED_VERSIONS,
                            TLSHelloExtensionType.COOKIE,
                            TLSHelloExtensionType.PSK_KEY_EXCHANGE_MODES,
                            TLSHelloExtensionType.CERTIFICATE_AUTHORITIES,
                            TLSHelloExtensionType.OID_FILTERS,
                            TLSHelloExtensionType.POST_HANDSHAKE_AUTH,
                            TLSHelloExtensionType.SIGNATURE_ALGORITHMS_CERT,
                            TLSHelloExtensionType.KEY_SHARE,
                            TLSHelloExtensionType.TRANSPARENCY_INFO,
                            TLSHelloExtensionType.CONNECTION_ID_DEPRECATED,
                            TLSHelloExtensionType.CONNECTION_ID,
                            TLSHelloExtensionType.EXTERNAL_ID_HASH,
                            TLSHelloExtensionType.EXTERNAL_SESSION_ID,
                            TLSHelloExtensionType.QUIC_TRANSPORT_PARAMETERS,
                            TLSHelloExtensionType.TICKET_REQUEST,
                            TLSHelloExtensionType.DNSSEC_CHAIN,
                            TLSHelloExtensionType.SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS,
                            TLSHelloExtensionType.RENEGOTIATION_INFORMATION):
            self.assertTrue(0 <= enumeration.value <= 0xFFFF)

        for code in range(0, 0x10000):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = TLSHelloExtensionType(code)

    def test_TLS(self):
        # TODO: Implement tests
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
