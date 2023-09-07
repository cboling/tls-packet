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

from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import DecodeError


class TestTLSHandshake(unittest.TestCase):
    def test_TLSHandshakeFrameDecodeFailures(self):
        with self.assertRaises(DecodeError):
            TLSHandshake.parse(None)

        with self.assertRaises(DecodeError):
            TLSHandshake.parse(b"")

        with self.assertRaises(DecodeError):
            # Unsupported message type
            TLSHandshake.parse(bytes.fromhex("AA0000080011223344556677"))

    def test_TLSHandshakeFrameMessageTypes(self):
        # Change underscores to spaces
        valid_codes = {0, 1, 2, 3, 4, 6, 8, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24, 254}
        for code in valid_codes:
            self.assertTrue(TLSHandshakeType.has_value(code))

            name = TLSHandshakeType(code).name()
            self.assertFalse('_' in name)

        for enumeration in (TLSHandshakeType.HELLO_REQUEST,
                            TLSHandshakeType.CLIENT_HELLO,
                            TLSHandshakeType.SERVER_HELLO,
                            TLSHandshakeType.HELLO_VERIFY_REQUEST,
                            TLSHandshakeType.SESSION_TICKET,
                            TLSHandshakeType.HELLO_RETRY_REQUEST,
                            TLSHandshakeType.ENCRYPTED_EXTENSIONS,
                            TLSHandshakeType.CERTIFICATE,
                            TLSHandshakeType.SERVER_KEY_EXCHANGE,
                            TLSHandshakeType.CERTIFICATE_REQUEST,
                            TLSHandshakeType.SERVER_HELLO_DONE,
                            TLSHandshakeType.CERTIFICATE_VERIFY,
                            TLSHandshakeType.CLIENT_KEY_EXCHANGE,
                            TLSHandshakeType.FINISHED,
                            TLSHandshakeType.CERTIFICATE_URL,
                            TLSHandshakeType.CERTIFICATE_STATUS,
                            TLSHandshakeType.SUPPLEMENTAL_DATA,
                            TLSHandshakeType.KEY_UPDATE,
                            TLSHandshakeType.MESSAGE_HASH):
            self.assertTrue(0 <= enumeration.value <= 255)

        for code in range(0, 256):
            if code not in valid_codes:
                with self.assertRaises(ValueError):
                    _ = TLSHandshakeType(code)


if __name__ == '__main__':
    unittest.main()