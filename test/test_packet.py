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
from mocks.mock_auth_socket import MockAuthSocket
from tls_packet.auth.cipher_suites import CipherSuite
from tls_packet.auth.security_params import TLSKeyExchangeTypes
from tls_packet.auth.tls import TLSv1_0, TLSv1_1, TLSv1_2
from tls_packet.auth.tls_client import TLSClient


class TestTLSClient(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.client_v10 = TLSClient(MockAuthSocket(),
                                   tls_version=TLSv1_0(),
                                   ciphers=None,
                                   random_data=FIXED_RANDOM,
                                   extensions=None,
                                   debug=True)
        cls.client_v11 = TLSClient(MockAuthSocket(),
                                   tls_version=TLSv1_1(),
                                   ciphers=None,
                                   random_data=FIXED_RANDOM,
                                   extensions=None,
                                   debug=True)
        cls.client_v12 = TLSClient(MockAuthSocket(),
                                   tls_version=TLSv1_2(),
                                   ciphers=None,
                                   random_data=FIXED_RANDOM,
                                   extensions=None,
                                   debug=True)
        # cls.client_v13 = TLSClient(MockAuthSocket(),
        #                            tls_version=TLSv1_3(),
        #                            ciphers=None,
        #                            random_data=FIXED_RANDOM,
        #                            extensions=None,
        #                            debug=True)

    def test_tls_client_versions(self):
        # Test pre-created version specific client used in other test cases
        for client in (self.client_v10, self.client_v11, self.client_v12):
            self.assertEqual(client.client_sequence_number, 0)
            self.assertEqual(client.server_sequence_number, 0)
            self.assertEqual(client.rx_security_parameters().client_random, FIXED_RANDOM)
            self.assertEqual(client.tx_security_parameters().client_random, FIXED_RANDOM)
            self.assertIsNone(client.rx_security_parameters().server_random)
            self.assertIsNone(client.tx_security_parameters().server_random)

            excluded = (TLSKeyExchangeTypes.DHE_PSK, TLSKeyExchangeTypes.ECDHE_PSK, TLSKeyExchangeTypes.RSA_PSK)
            ciphers = CipherSuite.get_cipher_suites_by_version(client.tls_version, excluded=excluded)
            self.assertNotEqual(len(ciphers), 0)

            self.assertEqual(client.ciphers, ciphers)
            self.assertIsNone(client.extensions)
            self.assertIsNone(client.server_certificates)


if __name__ == '__main__':
    unittest.main()
