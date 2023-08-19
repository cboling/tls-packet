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
import time
from typing import Union, Optional, Iterable

from tls_packet.auth.cipher_suites import CipherSuite
from tls_packet.auth.tls import TLS, TLSv1_2
from tls_packet.auth.tls_extension import HelloExtension
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import PacketPayload, PARSE_ALL


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


class TLSClientHello(TLSHandshake):
    """
    TLS Client Hello

      struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;
    """
    from tls_packet.auth.tls_client import TLSClient

    def __init__(self, state_machine: 'TLSClientStateMachine',
                 length: Optional[int] = None,  # For decode only
                 version: Optional[TLS] = None,
                 random_data: Optional[bytes] = None,
                 session_id: Optional[int] = 0,
                 ciphers: Optional[CipherSuite] = None,
                 compression: Optional[Iterable[int]] = (0,),
                 gmt_time: Optional[int] = 0,
                 extensions: Optional[Iterable[HelloExtension]] = None, **kwargs):
        super().__init__(TLSHandshakeType.CLIENT_HELLO,
                         length=length,
                         session=state_machine.session, **kwargs)

        self.version = version or int(state_machine.session.tls_version)
        self.random_bytes = random_data or os.urandom(32)
        self.session_id = session_id
        self.ciphers = ciphers or state_machine.session.ciphers
        self.compression = tuple(compression)
        self.gmt_unix_time = gmt_time or int(time.time())
        self.extensions = extensions or []

        # Error checks
        if self.version != int(TLSv1_2()):
            raise NotImplementedError("TLSClientHello: Only TLSv1.2 supported")

        if len(self.random_bytes) != 32:
            raise ValueError(f"TLSClientHello: Random must be exactly 32 bytes, received {len(self.random_bytes)}")

        if self.session_id > 32 or session_id < 0:
            raise ValueError(f"TLSClientHello: SessionID is an opaque value: 0..32, found, {self.session_id}")

        # Unsupported at this time
        if extensions:  # TODO: not yet supported
            raise NotImplementedError("Unsupported parameter")

    def __repr__(self):
        ciphers = ""
        first = True
        for k, v in self.ciphers.items():
            if not first:
                ciphers += ", "
            first = False
            ciphers += f"{k} [{v.get('id', 0):04x}]"

        return super().__repr__() + f", Version: {self.version}, Random: '{self.random_bytes.hex()}', Session ID: {self.session_id}" + \
            f", Ciphers: Len[{len(self.ciphers)}]: {ciphers}, Extensions: {self.extensions}"

    @property
    def client(self) -> TLSClient:
        return self._session

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
        return PacketPayload.parse(frame, *args, **kwargs)

    def pack(self, max_depth: Optional[int] = PARSE_ALL, payload: Optional[Union[bytes, None]] = None) -> bytes:
        # Version + Random + Length of session ID
        buffer = struct.pack("!H", self.version) + self.random_bytes + struct.pack("!B", self.session_id)

        # Add the ciphers supported. 2 bytes per cipher ID
        buffer += struct.pack("!H", 2 * len(self.ciphers))
        for cipher in self.ciphers.values():
            buffer += struct.pack("!H", cipher["id"])

        # Add the compression methods supported
        buffer += struct.pack("!B", len(self.compression))
        for method in self.compression:
            buffer += struct.pack("!B", method)

        # Add any extensions
        # TODO: HACK:    NEED SOMETHING IN THE EXTENSIONS BELOW REQUIRED TO GET THIS ALL TO WORK WITH FREERADIUS...
        # if self.extensions:
        ec_points_formats = "000b000403" + "00" + "01" + "02"  # uncompressed, ansiX962_compressed_prime, ansiX962_compressed_char2
        supported_groups = "000a000c000a" + "001d" + "0017" + "001e" + "0019" + "0018"  # x25519, secp256r1, x448, secp521r1, secp384r1
        encrypt_then_mac = "00160000"
        extended_master_secret = "00170000"
        # And 23 signature hash algorithms
        signature_algorithms = "000d0030002e040305030603080708080809080a080b080408050806040105" + \
                               "010601030302030301020103020202040205020602"
        ext_hex = ec_points_formats + supported_groups + encrypt_then_mac + extended_master_secret + signature_algorithms

        ext_data = bytes.fromhex(ext_hex)
        # ext_data = b''
        # for ext in self.extensions:
        #     # TODO: Need to have a subclass to handle these
        #     ext_data += ext.pack()
        #     raise NotImplementedError("NOT SUPPORTED YET")
        buffer += struct.pack(f"!H{len(ext_data)}s", len(ext_data), ext_data)

        return super().pack(payload=buffer)
