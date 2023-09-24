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

import struct
import sys
from typing import Optional

from tls_packet.auth.eap import EapPacket, EapType
from tls_packet.packet import DecodeError


class EapTls(EapPacket):
    _eap_type = EapType.EAP_TLS

    LENGTH_FLAG_MASK = 0x80
    MORE_FLAG_MASK = 0x40
    START_FLAG_MASK = 0x20
    ALL_FLAG_MASK = LENGTH_FLAG_MASK | MORE_FLAG_MASK | START_FLAG_MASK

    def __init__(self, flags: Optional[int] = 0, tls_length: Optional[int] = 0, payload: Optional[bytes] = None, **kwargs):
        import sys
        print(f"eapTls.__init__: entry, flags: {flags}, tls_len: {tls_length}", file=sys.stderr)

        super().__init__(**kwargs)
        self._flags = flags
        self._tls_length = tls_length
        self._tls_data = payload

        if flags & ~EapTls.ALL_FLAG_MASK:
            raise DecodeError(f"EapTls: Invalid flags value: {flags:#02x}")

    @property
    def flags(self) -> int:
        return self._flags

    @property
    def tls_length(self) -> int:
        return self._tls_length

    @property
    def tls_data(self) -> bytes:
        return self._tls_data

    @property
    def length_flag(self) -> bool:
        return self._flags & self.LENGTH_FLAG_MASK == self.LENGTH_FLAG_MASK

    @property
    def more_flag(self) -> bool:
        return self._flags & self.MORE_FLAG_MASK == self.MORE_FLAG_MASK

    @property
    def start_flag(self) -> bool:
        return self._flags & self.START_FLAG_MASK == self.START_FLAG_MASK

    # Following four are for Scapy decode compatibility
    L = length_flag
    M = more_flag
    S = start_flag
    tls_message_len = tls_length

    def pack(self, **argv) -> bytes:
        buffer = struct.pack("!B", self._flags)

        if self.length_flag:
            print(f"flags and data:  {self._flags:02x}, len: {self._tls_length}", file=sys.stderr)
            buffer += struct.pack("!I", self._tls_length) + self._tls_data

        print(f"eap-tls buffer: {buffer.hex()}", file=sys.stderr)
        return super().pack(payload=buffer)

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapTls':
        """
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Code          | Identifier    | Length                        |  <- EAP Layer
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Type          | Flags         | TLS Message Length               <- EAP-TLS Layer (This protocol layer)
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | TLS Message Length            | TLS Data...
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        length = len(frame)
        required = 1  # TLS Message Length only included if 'L' flag bit is set
        import sys
        print(f"eapTls.parse: entry, frame: {frame.hex()}", file=sys.stderr)

        if length < required:
            raise DecodeError(f"EapTls: message truncated: Expected at least {required} bytes, got: {length}")

        flags = int.from_bytes(frame[0:1], 'big')

        if flags & EapTls.LENGTH_FLAG_MASK == EapTls.LENGTH_FLAG_MASK:
            required += 4

            if length < required:
                raise DecodeError(f"EapTls: message truncated: Expected at least {required} bytes, got: {length}")

            length = int.from_bytes(frame[1:5], 'big')
            payload = frame[5:5 + length]

        else:
            length = 0
            payload = None

        return EapTls(flags=flags, length=length, payload=payload, **kwargs)
