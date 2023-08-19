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
from typing import Union, Optional, List

from tls_packet.auth.security_params import SecurityParameters, TLSCompressionMethod
from tls_packet.auth.tls import TLS, TLSv1_0
from tls_packet.packet import Packet, PacketPayload, DecodeError, PARSE_ALL


class TLSRecordContentType(IntEnum):
    """
    TLS Record Content Codes
    """
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class TLSRecord(Packet):
    """
    Base TLS Record class

       struct {
           ContentType type;
           ProtocolVersion version;
           uint16 length;
        ... type specific data here
    """

    def __init__(self, content_type: TLSRecordContentType, next_layer: 'Packet',
                 tls_version: Optional[TLS] = None,
                 length: Optional[Union[int, None]] = None,
                 session=None, **kwargs):

        super().__init__(layers=(next_layer,), **kwargs)
        self._session = session
        self._content_type = content_type
        self._msg_length = length

        # See RFC 8446 for 'version' below. For backwards compatibility, allowing a client to advertise TLS 1.3 support
        # while still being able to contact servers that only support older versions, the TLS Record version is
        # often set to V1.0 instead of the actual TLS version supported.  The entries in the record (next layer
        # higher will have proper/latest version numbers. The backward compatibility constraint isn't just
        # about servers, but also about firewalls and other network equipment that only let traffic through
        # that they recognize as being "good" TLS. Quite a bit of software rejects version numbers that are
        # higher than what they know is "good", which would have blocked TLS 1.3 traffic if TLS 1.3 had used the logical
        # version numbers.

        self._version = tls_version or TLSv1_0()

        if self._version is None:
            raise ValueError("TLSRecord: TLS Version not specified. Must be specified or provided by associated client/server session")

    def __repr__(self):
        return f"{self.__class__.__qualname__}: Type: {self._content_type}, Len: {self._msg_length}"

    @property
    def length(self) -> int:
        return self._msg_length if self._msg_length is not None else len(bytes(self))

    @property
    def session(self) -> Union['TLSClient', 'TLSServer']:
        return self._session

    @property
    def content_type(self) -> TLSRecordContentType:
        return self._content_type

    @staticmethod
    def parse(frame: bytes, security_params: SecurityParameters, *args, **kwargs) -> Union[List['TLSRecord'], None]:
        """
            https://www.ietf.org/rfc/rfc5246.txt

            A.1.  Record Layer

                   struct {
                       uint8 major;
                       uint8 minor;
                   } ProtocolVersion;

                   ProtocolVersion version = { 3, 3 };     /* TLS v1.2*/

                   enum {
                       change_cipher_spec(20), alert(21), handshake(22),
                       application_data(23), (255)
                   } ContentType;

                   struct {
                       ContentType type;
                       ProtocolVersion version;
                       uint16 length;
                       opaque fragment[TLSPlaintext.length];
                   } TLSPlaintext;

                   struct {
                       ContentType type;
                       ProtocolVersion version;
                       uint16 length;
                       opaque fragment[TLSCompressed.length];
                   } TLSCompressed;

                   struct {
                       ContentType type;
                       ProtocolVersion version;
                       uint16 length;
                       select (SecurityParameters.cipher_type) {
                           case stream: GenericStreamCipher;
                           case block:  GenericBlockCipher;
                           case aead:   GenericAEADCipher;
                       } fragment;
                   } TLSCiphertext;

                   stream-ciphered struct {
                       opaque content[TLSCompressed.length];
                       opaque MAC[SecurityParameters.mac_length];
                   } GenericStreamCipher;
                   struct {
                       opaque IV[SecurityParameters.record_iv_length];
                       block-ciphered struct {
                           opaque content[TLSCompressed.length];
                           opaque MAC[SecurityParameters.mac_length];
                           uint8 padding[GenericBlockCipher.padding_length];
                           uint8 padding_length;
                       };
                   } GenericBlockCipher;

                   struct {
                      opaque nonce_explicit[SecurityParameters.record_iv_length];
                      aead-ciphered struct {
                          opaque content[TLSCompressed.length];
                      };
                   } GenericAEADCipher;
        """
        if frame is None:
            raise DecodeError("TLSHandshake.parse: Called with frame = None")

        if len(frame) < 1:
            raise DecodeError(f"TLSHandshake: header truncated, need minimum of 1 bytes, found: {len(frame)}")

        compression = security_params.compression_algorithm
        try:
            record_list = []

            while len(frame) > 0:
                from tls_packet.auth.tls_record import TLSChangeCipherSpecRecord, TLSAlertRecord, \
                    TLSHandshakeRecord, TLSApplicationDataRecord

                content_type = TLSRecordContentType(frame[0])
                record_type = {
                    TLSRecordContentType.CHANGE_CIPHER_SPEC: TLSChangeCipherSpecRecord,
                    TLSRecordContentType.ALERT:              TLSAlertRecord,
                    TLSRecordContentType.HANDSHAKE:          TLSHandshakeRecord,
                    TLSRecordContentType.APPLICATION_DATA:   TLSApplicationDataRecord,
                }.get(content_type)
                print(f"TLSRecord:parse. Before Decompression: {frame.hex()}")
                record = record_type.parse(frame, compression, *args, **kwargs)

                if record is None:
                    DecodeError(f"Failed to decode TLSRecord. {len} records so far and remaining frame length was {len(frame)}")

                record_list.append(record)
                record_len = record.length + 5  # TLS Record header is 5 octets
                if compression != TLSCompressionMethod.NULL_METHOD:
                    print("TODO: the advancement in the original frame is corrected even if compressed, but the 'length' stored")
                    print("TODO: in the record is the original compressed length.  We need to fix that here")  # TODO: support compression
                frame = frame[record_len:]
                print(f"TLSRecord: Saved record to list: {record}")
                print(f"TLSRecord: {len(frame)} bytes remaining")
                print(f"TLSRecord: Remaining frame: {frame.hex()}")

            return record_list

        except ValueError as e:
            raise DecodeError from e

    def pack(self, payload: Optional[bytes] = None) -> bytes:
        """ Convert to a packet for transmission """
        buffer = struct.pack("!B", self._content_type) + bytes(self._version)
        if payload:
            self._msg_length = len(payload)
            payload_len = struct.pack("!H", self._msg_length)
            buffer += payload_len + payload
        return buffer

    @staticmethod
    def decompress(compressed_payload: bytes, compression: TLSCompressionMethod) -> bytes:
        if compression == TLSCompressionMethod.NULL_METHOD:
            return compressed_payload

        elif compression == TLSCompressionMethod.DEFLATE_METHOD:
            # TODO: Support if needed.  See RFC 3749 notes on deflate state across sessions.
            raise NotImplementedError("Deflate method not yet supported")

        raise DecodeError(f"Unsupported TLS Compression Method: {compression}")

    def __bytes__(self) -> bytes:
        return self.pack()


class TLSChangeCipherSpecRecord(TLSRecord):
    def __init__(self, data, **kwargs):
        super().__init__(TLSRecordContentType.CHANGE_CIPHER_SPEC, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL,
              compression: Optional[TLSCompressionMethod] = TLSCompressionMethod.NULL_METHOD) -> Union['TLSChangeCipherSpecRecord', None]:
        raise NotImplementedError("Not yet implemented")


class TLSAlertRecord(TLSRecord):
    def __init__(self, data, **kwargs):
        super().__init__(TLSRecordContentType.ALERT, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, compression, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union['TLSAlertRecord', None]:
        raise NotImplementedError("Not yet implemented")


class TLSHandshakeRecord(TLSRecord):
    from tls_packet.auth.tls_handshake import TLSHandshake

    def __init__(self, handshake: Union[TLSHandshake, PacketPayload], **kwargs):
        super().__init__(TLSRecordContentType.HANDSHAKE, handshake, **kwargs)
        # TODO: Do we need to save the handshake? or just leave it inside our layers...
        self._handshake = handshake

    def __repr__(self):
        return super().__repr__() + f", Handshake: [{self._handshake}]"

    def pack(self, **argv) -> bytes:
        return super().pack(payload=bytes(self._handshake))

    @staticmethod
    def parse(frame: bytes, compression, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union['TLSHandshakeRecord', None]:
        # Decompress if needed
        #     Type = frame[0]
        #  Version = frame[1..2]
        #   Length = frame[3..4]
        # Fragment = frame[5...]
        if len(frame) < 6:
            raise DecodeError(f"TLSHandshakeRecord: Truncated frame. Only {len(frame)} octets")

        tls_version = TLS.get_by_code(frame[1:3])
        if tls_version is None:
            raise DecodeError(f"TLSHandshakeRecord: unrecognized TLS version '{frame[1:3]:#04x}'")

        msg_len = struct.unpack_from("!H", frame, 3)[0]
        if msg_len > len(frame) - 5:
            raise DecodeError(f"TLSHandshakeRecord: Truncated payload. Only {len(frame) - 7} octets. Message Header Length: {msg_len}")

        # TODO: Limit data passed to 5+msg_len below so we only pass this record
        payload = TLSRecord.decompress(frame[5:], compression)
        print(f"TLSRecord:parse: After decompression {compression}: {payload.hex()}")

        if max_depth > 0:
            # Parse the handshake message
            from tls_packet.auth.tls_handshake import TLSHandshake

            handshake = TLSHandshake.parse(payload, *args, max_depth=max_depth - 1, **kwargs)
        else:
            # Save it as blob data (note that we use the decompressed data)
            handshake = PacketPayload(payload, *args, **kwargs)

        return TLSHandshakeRecord(handshake, tls_version=tls_version, length=msg_len, original_frame=frame)


class TLSApplicationDataRecord(TLSRecord):
    def __init__(self, data, **kwargs):
        super().__init__(TLSRecordContentType.APPLICATION_DATA, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, compression, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union['TLSApplicationDataRecord', None]:
        raise NotImplementedError("Not yet implemented")
