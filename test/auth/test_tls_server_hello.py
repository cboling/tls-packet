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

from tls_packet.auth.tls import TLS, TLSv1_0, TLSv1_2
from tls_packet.auth.tls_handshake import TLSHandshake
from tls_packet.auth.tls_server_hello import TLSServerHello
from tls_packet.packet import DecodeError


class TestTLSServerHello(unittest.TestCase):
    @classmethod
    def setUp(cls):
        pass
        # cls.server = TLSServer(MockAuthSocket(),
        #                        tls_version=TLSv1_2(),
        #                        ciphers=None,
        #                        random_data=FIXED_RANDOM,
        #                        extensions=None,
        #                        debug=True)

    # def test_TLSServerHello_serialization(self):
    #     server = self.server
    #
    #     # Currently we act only as a client
    #     with self.assertRaises(NotImplementedError):
    #         hello = TLSServerHello(server)
    #         bytes(hello)

    def test_TLSServerHello_serialize_bad_value_checks(self):
        with self.assertRaises(ValueError):
            TLSServerHello(None, session_id=33)

        with self.assertRaises(ValueError):
            TLSServerHello(None, session_id=-1)

        with self.assertRaises(ValueError):
            TLSServerHello(None, random_data=os.urandom(8))  # too small

    def _server_hello_payload(self, version: TLS, session_id=0) -> str:
        # Payload copied from a TLS Server Hello from FreeRadius v3.0.20 to Ubuntu 20.04 WPA Supplicant
        version_data = bytes(version)
        hello_data = f"{version_data.hex()}"

        hello_data += "391c112416c4dee2aa08c579eb4803f77d9ecfdcb7fe7eb9bf0e9327640d11ca"
        hello_data += f"{session_id:02x}"  # Session ID
        hello_data += "c014"               # Cipher Suite (TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
        hello_data += "00"                 # Compression method (null)
        hello_data += "0015"               # Extension Length
        hello_data += "ff01000100"         # renegotiation_info                  # TODO: Need to support and code this
        hello_data += "000b000403000102"   # ec_points_formats
        hello_data += "00160000"           # encrypt_then_mac
        hello_data += "00170000"           # extended_master_secret
        return hello_data

    def test_TLSServerHello_decode(self):
        supported = (TLSv1_2(), )
        for version in supported:
            # Construct frame
            print(f"Version: {version}", file=sys.stderr)
            hello_payload = self._server_hello_payload(version)
            hello_header = f"02{int(len(hello_payload)/2):06x}"   # Header, only want 24-bits of length
            hello_frame = hello_header + hello_payload

            hello = TLSHandshake.parse(bytes.fromhex(hello_frame))

            self.assertIsNotNone(hello)
            self.assertIsInstance(hello, TLSServerHello)
            # TODO: Support further packet content testing and decoding

    # TODO: Re-enable below later
    # def test_TLSServerHello_decode_unsupported_versions(self):
    #     unsupported = (TLSv1_0(), TLSv1_1(), TLSv1_3())
    #     for version in unsupported:
    #         # Construct frame
    #         print(f"Version: {version}", file=sys.stderr)
    #         hello_payload = self._server_hello_payload(version)
    #         hello_header = f"02{int(len(hello_payload)/2):06x}"   # Header, only want 24-bits of length
    #         hello_frame = hello_header + hello_payload
    #
    #         with self.assertRaises(NotImplementedError):
    #             TLSHandshake.parse(bytes.fromhex(hello_frame))

    def test_TLSServerHello_decode_bad_session_id(self):
        version = TLSv1_2()

        for session_id in range(33, 255):
            # Construct frame
            print(f"Session ID: {session_id}", file=sys.stderr)
            hello_payload = self._server_hello_payload(version, session_id=session_id)
            hello_header = f"02{int(len(hello_payload)/2):06x}"   # Header, only want 24-bits of length
            hello_frame = hello_header + hello_payload

            with self.assertRaises(DecodeError):
                TLSHandshake.parse(bytes.fromhex(hello_frame))

    def test_TLSServerHello_decode_truncated(self):
        version = TLSv1_0()
        hello_payload = self._server_hello_payload(version)
        hello_header = f"02{int(len(hello_payload)/2):06x}"   # Header, only want 24-bits of length
        minimum = 1 + 3 + 2 + 32 + 1 + 2 + 1 + 1
        hello_frame = hello_header + hello_payload[:minimum-1]

        with self.assertRaises(DecodeError):
            TLSHandshake.parse(bytes.fromhex(hello_frame))

    def test_TLSServerHello_decode_direct_parse_fail(self):
        version = TLSv1_0()
        hello_payload = self._server_hello_payload(version)

        # Use 00 as message type and not 02
        hello_header = f"00{int(len(hello_payload)/2):06x}"   # Header, only want 24-bits of length
        hello_frame = hello_header + hello_payload

        with self.assertRaises(DecodeError):
            TLSServerHello.parse(bytes.fromhex(hello_frame))


if __name__ == '__main__':
    unittest.main()