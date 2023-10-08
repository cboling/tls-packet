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

from typing import Union, Optional

from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import DecodeError, PARSE_ALL


class TLSServerHelloDone(TLSHandshake):
    """
    TLS Server Hello Done Message

      The ServerHelloDone message is sent by the server to indicate the
      end of the ServerHello and associated messages.  After sending
      this message, the server will wait for a client response.

        struct { } ServerHelloDone;
    """

    def __init__(self, **kwargs):
        super().__init__(TLSHandshakeType.SERVER_HELLO_DONE, **kwargs)

    @staticmethod
    def parse(frame: bytes, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSServerHelloDone """
        required = 4
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSServerHelloDone: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.SERVER_HELLO_DONE:
            raise DecodeError(f"TLSSessionHello: Message type is not SERVER_HELLO_DONE. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')

        return TLSServerHelloDone(length=msg_len, original_frame=frame, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
