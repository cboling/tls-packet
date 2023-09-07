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
import sys
import unittest

from mocks.mock_auth_socket import MockAuthSocket
from mocks.mock_packet import FIXED_RANDOM
from mocks.util import assertGeneratedFrameEquals

from tls_packet.auth.cipher_suites import get_cipher_suites_by_version
from tls_packet.auth.tls import TLS, TLSv1_0, TLSv1_1, TLSv1_2, TLSv1_3
from tls_packet.auth.tls_client import TLSClient
from tls_packet.auth.tls_client_hello import TLSClientHello
from tls_packet.auth.tls_extension import HelloExtension
from tls_packet.auth.tls_handshake import TLSHandshake


# noinspection PyInterpreter
class TestTLSClientHello(unittest.TestCase):
    @classmethod
    def setUp(cls):
        cls.client = TLSClient(MockAuthSocket(),
                               tls_version=TLSv1_2(),
                               ciphers=None,
                               random_data=FIXED_RANDOM,
                               extensions=None,
                               debug=True)

    @staticmethod
    def _client_hello_payload(version: TLS) -> str:
        all = get_cipher_suites_by_version(TLSv1_2(), excluded=("PSK", ))
        ciphers = [cipher["id"] for cipher in all.values()]

        version_data = bytes(version)
        hello_data = f"{version_data.hex()}"
        hello_data += f"000102030405060708090a0b0c0d0e0f" +\
                     "101112131415161718191a1b1c1d1e1f"     # Fixed random
        hello_data += "00"                                  # Session ID
        hello_data += f"{len(ciphers)*2:04x}"               # Cipher Suite Len
        hello_data += ''.join(f"{c:04x}" for c in ciphers)  # Cipher Suites
        hello_data += "01"                                  # Compression Methods Len
        hello_data += "00"                                  # Compression Methods

        # TODO: HACK:    NEED SOMETHING IN THE EXTENSIONS BELOW REQUIRED TO GET THIS ALL TO WORK WITH FREERADIUS...
        #if self.extensions:
        ec_points_formats = "000b000403" + "00" + "01" + "02"                           # uncompressed, ansiX962_compressed_prime, ansiX962_compressed_char2
        supported_groups = "000a000c000a" + "001d" + "0017" + "001e" + "0019" + "0018"  # x25519, secp256r1, x448, secp521r1, secp384r1
        encrypt_then_mac = "00160000"
        extended_master_secret = "00170000"
        # And 23 signature hash algorithms
        signature_algorithms = "000d0030002e040305030603080708080809080a080b080408050806040105" + \
                               "010601030302030301020103020202040205020602"
        ext_hex = ec_points_formats + supported_groups + encrypt_then_mac + extended_master_secret + signature_algorithms
        hello_data += f"{int(len(ext_hex)/2):04x}{ext_hex}"    # Extensions

        return hello_data

    def test_TLSClientHello_serialization(self):
        supported = (TLSv1_2(),)         # TODO: Get TLSv1_0 working
        for version in supported:
            print(f"Version: {version}", file=sys.stderr)
            client = TLSClient(MockAuthSocket(), tls_version=version, random_data=FIXED_RANDOM)

            # Construct expected frame
            hello_payload = self._client_hello_payload(version)
            hello_header = f"01{int(len(hello_payload) / 2):06x}"      # Header, only 24-bits of length
            expected = hello_header + hello_payload

            hello = TLSClientHello(client, random_data=FIXED_RANDOM)
            assertGeneratedFrameEquals(self, hello.pack(), expected)

            # And the bytes method
            assertGeneratedFrameEquals(self, bytes(hello), expected)

            # Session and client are the same
            self.assertIsNotNone(hello.client)
            self.assertEqual(hello.client, hello.session)

            # Can use repr and/or str on the object
            self.assertNotEqual(repr(hello), "")
            self.assertNotEqual(str(hello), "")

    def test_TLSClientHello_serialization_unsupported_versions(self):
        unsupported = (TLSv1_0(), TLSv1_1(), TLSv1_3())
        for version in unsupported:
            print(f"Version: {version}", file=sys.stderr)
            with self.assertRaises(NotImplementedError):
                client = TLSClient(MockAuthSocket(), tls_version=version, random_data=FIXED_RANDOM)
                TLSClientHello(client, random_data=FIXED_RANDOM)

    def test_TLSClientHello_serialization_invalid_random(self):
        client = TLSClient(MockAuthSocket(), random_data=FIXED_RANDOM)
        with self.assertRaises(ValueError):
            TLSClientHello(client, random_data=os.urandom(8))  # too small

    def test_TLSClientHello_serialization_bad_session_id(self):
        client = TLSClient(MockAuthSocket(), random_data=FIXED_RANDOM)

        with self.assertRaises(ValueError):
            TLSClientHello(client, random_data=FIXED_RANDOM, session_id=-1)

        for session_id in range(33, 255):
            print(f"Session ID: {session_id}", file=sys.stderr)
            with self.assertRaises(ValueError):
                TLSClientHello(client, random_data=FIXED_RANDOM, session_id=session_id)

    def test_TLSClientHello_serialization_extensions_not_supported(self):
        client = TLSClient(MockAuthSocket(), random_data=FIXED_RANDOM)

        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            extensions = [HelloExtension(header=6, data=b'')]
            TLSClientHello(client, random_data=FIXED_RANDOM, extensions=extensions)

    def test_TLSClientHello_decode(self):
        # Currently we act only as a client
        with self.assertRaises(NotImplementedError):
            # TODO: Not yet supported
            frame = "01000004010303"  # Enough to throw an exception
            TLSHandshake.parse(bytes.fromhex(frame))


if __name__ == '__main__':
    unittest.main()