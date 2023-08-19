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
from enum import IntEnum
from typing import Union, Optional

from tls_packet.packet import Packet, DecodeError


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
#
#       enum {
#           hello_request(0), client_hello(1), server_hello(2),
#           certificate(11), server_key_exchange (12),
#           certificate_request(13), server_hello_done(14),
#           certificate_verify(15), client_key_exchange(16),
#           finished(20), (255)
#       } HandshakeType;
#

class TLSHandshakeType(IntEnum):
    """
    TLS Handshake Message Codes

    The TLS Handshake Protocol is one of the defined higher-level clients
    of the TLS Record Protocol.  This protocol is used to negotiate the
    secure attributes of a session.  Handshake messages are supplied to
    the TLS record layer, where they are encapsulated within one or more
    TLSPlaintext structures, which are processed and transmitted as
    specified by the current active session state.

       enum {
           hello_request(0), client_hello(1), server_hello(2),
           certificate(11), server_key_exchange (12),
           certificate_request(13), server_hello_done(14),
           certificate_verify(15), client_key_exchange(16),
           finished(20), (255)
       } HandshakeType;
    """
    HELLO_REQUEST = 0  # Deprecated in v1.3
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3  # Deprecated in v1.3
    SESSION_TICKET = 4
    HELLO_RETRY_REQUEST = 6  # Deprecated in v1.3
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12  # Deprecated in v1.3
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14  # Deprecated in v1.3
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16  # Deprecated in v1.3
    FINISHED = 20
    CERTIFICATE_URL = 21  # Deprecated in v1.3
    CERTIFICATE_STATUS = 22  # Deprecated in v1.3
    SUPPLEMENTAL_DATA = 23  # Deprecated in v1.3
    KEY_UPDATE = 24
    MESSAGE_HASH = 254  # Added in v1.4

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class TLSHandshake(Packet):
    """
    Base TLS Handshake class

        struct {
            HandshakeType msg_type;    /* handshake type */
            uint24 length;             /* bytes in message */
            select (HandshakeType) {
                case hello_request:       HelloRequest;
                case client_hello:        ClientHello;
                case server_hello:        ServerHello;
                case certificate:         Certificate;
                case server_key_exchange: ServerKeyExchange;
                case certificate_request: CertificateRequest;
                case server_hello_done:   ServerHelloDone;
                case certificate_verify:  CertificateVerify;
                case client_key_exchange: ClientKeyExchange;
                case finished:            Finished;
            } body;
        } Handshake;

        typedef struct __attribute__((packed)) {
        	uint8_t content_type;  // 0x16
            uint16_t version;
            uint16_t length;
        } TLSRecord;
    """

    def __init__(self, msg_type: TLSHandshakeType,
                 length: Optional[Union[int, None]] = None,
                 session: Optional[Union['TLSClient', 'TLSServer']] = None, **kwargs):
        super().__init__(**kwargs)
        self._session = session
        self._msg_type = msg_type
        self._msg_length = length

    def __repr__(self):
        return f"{self.__class__.__qualname__}: Type: {self._msg_type}, Len: {self._msg_length}"

    @property
    def session(self) -> Union["TLSClient", "'TLSServer'", None]:
        return self._session

    @property
    def msg_type(self) -> TLSHandshakeType:
        return self._msg_type

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> Union['TLSHandshake', None]:
        if frame is None:
            raise DecodeError("TLSHandshake.parse: Called with frame = None")

        if len(frame) < 1:
            raise DecodeError(f"TLSHandshake: header truncated, need minimum of 1 bytes, found: {len(frame)}")

        try:
            # from tls_packet.auth.tls_finish import TLSFinish
            from tls_packet.auth.tls_hello import TLSHelloRequest
            from tls_packet.auth.tls_client_hello import TLSClientHello
            from tls_packet.auth.tls_server_hello import TLSServerHello
            from tls_packet.auth.tls_server_key_exchange import TLSServerKeyExchange
            from tls_packet.auth.tls_server_hello_done import TLSServerHelloDone
            from tls_packet.auth.tls_certificate import TLSCertificate
            from tls_packet.auth.tls_certificate_request import TLSCertificateRequest
            from tls_packet.auth.tls_certificate_verify import TLSCertificateVerify

            msg_type = TLSHandshakeType(frame[0])
            msg_class = {
                TLSHandshakeType.HELLO_REQUEST:       TLSHelloRequest,
                TLSHandshakeType.CLIENT_HELLO:        TLSClientHello,
                TLSHandshakeType.SERVER_HELLO:        TLSServerHello,
                # TLSHandshakeType.HELLO_VERIFY_REQUEST: TLS,
                # TLSHandshakeType.SESSION_TICKET:       TLS,
                # TLSHandshakeType.HELLO_RETRY_REQUEST:  TLS,
                # TLSHandshakeType.ENCRYPTED_EXTENSIONS: TLS,
                TLSHandshakeType.CERTIFICATE:         TLSCertificate,
                TLSHandshakeType.SERVER_KEY_EXCHANGE: TLSServerKeyExchange,
                TLSHandshakeType.CERTIFICATE_REQUEST: TLSCertificateRequest,
                TLSHandshakeType.SERVER_HELLO_DONE:   TLSServerHelloDone,
                TLSHandshakeType.CERTIFICATE_VERIFY:  TLSCertificateVerify,
                # TLSHandshakeType.CLIENT_KEY_EXCHANGE:  TLS,
                # TLSHandshakeType.FINISHED:             TLSFinish,
                # TLSHandshakeType.CERTIFICATE_URL:      TLS,
                # TLSHandshakeType.CERTIFICATE_STATUS:   TLS,
                # TLSHandshakeType.SUPPLEMENTAL_DATA:    TLS,
                # TLSHandshakeType.KEY_UPDATE:           TLS,
                # TLSHandshakeType.MESSAGE_HASH:         TLS,
            }.get(msg_type)
            # This is not a layer, the message parsed below is the handshake layer. So do not
            # decrement max_depth or check if it is zero
            print(f"msg_class is: {msg_class}")
            return msg_class.parse(frame, *args, **kwargs) if msg_class else None

        except (ValueError, KeyError) as e:
            raise DecodeError from e

        except Exception as _e:
            raise

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        buffer = struct.pack("!B", self.msg_type)

        if payload is not None:
            self._msg_length = len(payload)
            payload_len = struct.pack("!I", self._msg_length)  # We only want 24-bits
            buffer += payload_len[1:] + payload
        return buffer

    def to_record(self) -> 'TLSHandshakeRecord':
        from tls_packet.auth.tls_record import TLSHandshakeRecord
        """ Convert a TLS Handshake object to its corresponding TLSHandshakeRecord """

        return TLSHandshakeRecord(self, session=self.session)
