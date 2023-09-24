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

import os
import struct
from typing import Union, Optional, Iterable
import sys

from tls_packet.auth.cipher_suites import CipherSuite
from tls_packet.auth.security_params import TLSCompressionMethod
from tls_packet.auth.tls import TLSv1_2, TLSv1_3
from tls_packet.auth.tls_extension import TLSHelloExtension
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_extension import TLSHelloExtension
from tls_packet.packet import PacketPayload, DecodeError, PARSE_ALL


# https://www.ietf.org/rfc/rfc5246.txt
#
#             The Transport Layer Security (TLS) Protocol
#                            Version 1.2
#
# Handshake Protocol
#
#      Client                                               Server
#
#      ClientHello                  -------->
#                                                      ServerHello
#                                                     Certificate*
#                                               ServerKeyExchange*
#                                              CertificateRequest*
#                                   <--------      ServerHelloDone
#      Certificate*
#      ClientKeyExchange
#      CertificateVerify*
#      [ChangeCipherSpec]
#      Finished                     -------->
#                                               [ChangeCipherSpec]
#                                   <--------             Finished
#      Application Data             <------->     Application Data
#
#    The TLS Handshake Protocol is one of the defined higher-level clients
#    of the TLS Record Protocol.  This protocol is used to negotiate the
#    secure attributes of a session.  Handshake messages are supplied to
#    the TLS record layer, where they are encapsulated within one or more
#    TLSPlaintext structures, which are processed and transmitted as
#    specified by the current active session state.


class TLSServerHello(TLSHandshake):
    """
    TLS Server Hello Message

    struct {
          ProtocolVersion server_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suite;
          CompressionMethod compression_method;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ServerHello;
    """

    def __init__(self, session,
                 cipher: Optional[Union[CipherSuite]] = None,
                 length: Optional[int] = None,  # For decode only
                 version: Optional[int] = 0,
                 random_data: Optional[Union[bytes, None]] = None,
                 compression: Optional[TLSCompressionMethod] = TLSCompressionMethod.NULL_METHOD,
                 session_id: Optional[int] = 0,
                 extensions: Optional[Union[Iterable[TLSHelloExtension], None]] = None, **kwargs):
        super().__init__(TLSHandshakeType.SERVER_HELLO, length=length, session=session, **kwargs)

        # Error checks
        self.version = version or (int(session.tls_version) if session is not None else int(TLSv1_2()))
        self._random_bytes = random_data or os.urandom(32)
        self._session_id = session_id
        self._cipher = cipher
        self._compression = TLSCompressionMethod(compression)
        self.extensions = extensions or []

        # TODO: In other client, it created cipher suite with
        # self.cipher_suite = CipherSuite.get_from_id(self.tls_version, self.client_random, self.server_random,
        #                                             self.server_certificate, server_cipher_suite)
        # And used it supported the parse_key_exchange method

        # Error checks
        if self.version == int(TLSv1_3()):
            raise NotImplementedError("TLSServerHello: TLSv1.3 not yet supported")

        if len(self._random_bytes) != 32:
            raise ValueError(f"TLSServerHello: Random must be exactly 32 bytes, received {len(self.random_bytes)}")

        if self._session_id > 32 or session_id < 0:
            raise ValueError(f"TLSServerHello: SessionID is an opaque value: 0..32, found, {self._session_id}")

    @property
    def cipher_suite(self) -> CipherSuite:
        """ Cipher Suite selected by the server """
        return self._cipher

    @property
    def compression_method(self) -> TLSCompressionMethod:
        """ Compression method used """
        return self._compression

    @property
    def session_id(self) -> int:
        return self._session_id

    @property
    def random_bytes(self) -> bytes:
        return self._random_bytes

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSSessionHello """

        # type(1) + length(3) + version(2), random(32) + session(1) + cipher_suite(2) + compression(1) + extension_length + extensions(0..65536)
        required = 1 + 3 + 2 + 32 + 1 + 2 + 1 + 2
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSServerHello: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.SERVER_HELLO:
            raise DecodeError(f"TLSSessionHello: Message type is not SERVER_HELLO. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')
        offset = 4
        version, = struct.unpack_from("!H", frame, offset)
        offset = 6
        random_data = frame[offset:offset + 32]
        offset += 32
        session_id, cipher, compression, extension_length = struct.unpack_from("!BHBH", frame, offset)
        offset += 6
        compression = TLSCompressionMethod(compression)
        extensions = TLSHelloExtension.parse(frame[offset:offset + extension_length]) if extension_length else None
        # offset += extension_length

        if session_id > 32:
            raise DecodeError(f"TLSServerHello: SessionID is an opaque value: 0..32, found, {session_id}")

        return TLSServerHello(None, cipher, version=version, length=msg_len, random_data=random_data, compression=compression,
                              session_id=session_id, extensions=extensions, original_frame=frame, **kwargs)  # TODO: later ->  , extensions = extensions)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
