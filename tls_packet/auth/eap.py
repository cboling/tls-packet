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
from typing import Union, Optional, List, Any

from tls_packet.packet import Packet, PacketPayload, DecodeError, PARSE_ALL


class EapCode(IntEnum):
    EAP_REQUEST  = 1
    EAP_RESPONSE = 2
    EAP_SUCCESS  = 3
    EAP_FAILURE  = 4
    EAP_INITIATE = 5
    EAP_FINISH   = 6

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


class EapType(IntEnum):
    EAP_IDENTITY = 1
    EAP_LEGACY_NAK = 3
    EAP_MD5_CHALLENGE = 4
    EAP_ONE_TIME_PASSWORD = 5
    EAP_GENERIC_TOKEN_CARD = 6
    EAP_TLS = 13
    EAP_TTLS = 21
    EAP_PEAP = 25

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


class EAP(Packet):
    """
    EAP Packet Class
    """

    def __init__(self, eap_code: EapCode, eap_id: Optional[int] = 256, length: Optional[int] = None, **kwargs):

        super().__init__(**kwargs)
        self._eap_code = EapCode(eap_code)
        self._msg_length = length
        self._eap_id = eap_id

    def __repr__(self):
        return f"{self.__class__.__qualname__}: Type: {self._eap_code}({self._eap_type}), Len: {self._msg_length}"

    @property
    def length(self) -> int:
        return self._msg_length if self._msg_length is not None else len(bytes(self))

    @property
    def eap_code(self) -> EapCode:
        return self._eap_code

    @property
    def eap_type(self) -> EapType:
        return self._eap_type

    @property
    def eap_id(self) -> int:
        return self._eap_id

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EAP':
        """
        """
        if frame is None:
            raise DecodeError("EAP.parse: Called with frame = None")

        if len(frame) < 4:
            raise DecodeError(f"EAP: header truncated, need minimum of 4 bytes, found: {len(frame)}")

        code, ident, length = struct.unpack_from("!BBH", frame)

        try:
            eap_code = EapCode(code)

            frame_type = {
                EapCode.EAP_REQUEST:  EapRequest,
                EapCode.EAP_RESPONSE: EapResponse,
                EapCode.EAP_SUCCESS:  EapSuccess,
                EapCode.EAP_FAILURE:  EapFailure,
                EapCode.EAP_INITIATE: EapInitiate,
                EapCode.EAP_FINISH:   EapFinish,
            }.get(eap_code)

            print(f"EAPOL:parse. Before Decompression: {frame.hex()}")
            packet = frame_type.parse(frame, *args, eap_id=ident, lenght=length, **kwargs)

            if packet is None:
                raise DecodeError(f"Failed to decode EAPOL: {frame_type}")

            return packet

        except ValueError as e:
            raise DecodeError from e

    @staticmethod
    def parse_eap_type(eap_type: EapType, frame: bytes, *args, **kwargs) -> Packet:
        try:
            parser = {
                EapType.EAP_IDENTITY:           EapIdentity,
                EapType.EAP_LEGACY_NAK:         EapLegacyNak,
                EapType.EAP_MD5_CHALLENGE:      EapMd5Challenge,
                EapType.EAP_ONE_TIME_PASSWORD:  EapOneTimePassword,
                EapType.EAP_GENERIC_TOKEN_CARD: EapGenericTokenCard,
                EapType.EAP_TLS:                EapTls,
                EapType.EAP_TTLS:               EapTtls,
            }.get(eap_type)

            print(f"EAPOL:parse. Before Decompression: {frame.hex()}")
            packet = parser.parse(frame, *args, **kwargs)

            if packet is None:
                raise DecodeError(f"Failed to decode EAPOL: {parser}")

            return packet

        except ValueError as e:
            raise DecodeError from e

    def pack(self, payload: Optional[bytes] = None) -> bytes:
        """ Convert to a packet for transmission """
        msg_len = self._msg_length or len(payload) if payload else 0
        buffer = struct.pack("!BBH", self._eap_code, self._eap_type, msg_len)

        if payload:
            buffer += payload
        return buffer


class EapRequest(EAP):
    def __init__(self, eap_type_data: Union['EapPacket', PacketPayload], **kwargs):
        super().__init__(EapCode.EAP_REQUEST, **kwargs)
        self._eap_type = EapType(eap_type_data.eap_type)

        # TODO: Treat next in future as a layer
        self._eap_type_data = eap_type_data

        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, length: Optional[int] = None, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> 'EapRequest':
        offset = 4
        required = offset + length

        if len(frame) < required:
            raise DecodeError(f"EapRequest: message truncated: Expected at least {required} bytes, got: {len(frame)}")

        payload_data = frame[offset: required]
        eap_type, = struct.unpack("!B", payload_data)
        eap_type = EapType(eap_type)

        if max_depth > 0:
            # Parse the handshake message
            payload = EapRequest.parse_eap_type(eap_type, payload_data, *args, max_depth=max_depth-1, **kwargs)
        else:
            # Save it as blob data (note that we use the decompressed data)
            payload = PacketPayload(payload_data, *args, **kwargs)

        return EapRequest(eap_type, payload, length=length, **kwargs)


class EapResponse(EAP):
    def __init__(self, eap_type_data: Union['EapPacket', PacketPayload], **kwargs):
        super().__init__(EapCode.EAP_RESPONSE, **kwargs)
        self._eap_type = EapType(eap_type_data.eap_type)

        # TODO: Treat next in future as a layer
        self._eap_type_data = eap_type_data

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, length: Optional[int] = None, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union['EapResponse', None]:
        offset = 4
        required = offset + length

        if len(frame) < required:
            raise DecodeError(f"EapResponse: message truncated: Expected at least {required} bytes, got: {len(frame)}")

        payload_data = frame[offset: required]
        eap_type, = struct.unpack("!B", payload_data)
        eap_type = EapType(eap_type)

        if max_depth > 0:
            # Parse the handshake message
            payload = EapRequest.parse_eap_type(eap_type, payload_data, *args, max_depth=max_depth-1, **kwargs)
        else:
            # Save it as blob data (note that we use the decompressed data)
            payload = PacketPayload(payload_data, *args, **kwargs)

        return EapResponse(eap_type, payload, length=length, **kwargs)


class EapSuccess(EAP):
    def __init__(self, **kwargs):
        super().__init__(EapCode.EAP_SUCCESS, **kwargs)

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapSuccess':
        return EapSuccess(**kwargs)


class EapFailure(EAP):
    def __init__(self, **kwargs):
        super().__init__(EapCode.EAP_FAILURE, **kwargs)

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapFailure':
        return EapFailure(**kwargs)


class EapInitiate(EAP):
    def __init__(self, **kwargs):
        super().__init__(EapCode.EAP_INITIATE, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapInitiate':
        raise NotImplementedError("Not yet implemented")


class EapFinish(EAP):
    def __init__(self, **kwargs):
        super().__init__(EapCode.EAP_FINISH, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapFinish':
        raise NotImplementedError("Not yet implemented")


class EapPacket(Packet):
    _eap_type = None

    @property
    def eap_type(self) -> EapType:
        return self._eap_type


class EapIdentity(EapPacket):
    _eap_type = EapType.EAP_IDENTITY

    def __init__(self, type_data: bytes, **kwargs):
        super().__init__(**kwargs)
        self._type_data = type_data

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, length: Optional[int] = None, **kwargs) -> 'EapIdentity':

        if len(frame) < length:
            raise DecodeError(f"EapIdentity: message truncated: Expected at least {length} bytes, got: {len(frame)}")

        type_data = frame[:length]
        return EapIdentity(type_data, length=length, **kwargs)


class EapLegacyNak(EapPacket):
    _eap_type = EapType.EAP_LEGACY_NAK

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(eap_code: EapCode, frame: bytes, *args, **kwargs) -> 'EapLegacyNak':
        raise NotImplementedError("Not yet implemented")


class EapMd5Challenge(EapPacket):
    _eap_type = EapType.EAP_MD5_CHALLENGE

    def __init__(self, challenge, extra_data, **kwargs):
        super().__init__(**kwargs)
        self._challenge = challenge
        self._extra_data = extra_data

    @property
    def challenge(self):
        return self._challenge

    @property
    def extra_data(self):
        return self._extra_data

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(eap_code: EapCode, frame: bytes, *args, **kwargs) -> 'EapMd5Challenge':
        raise NotImplementedError("Not yet implemented")


class EapOneTimePassword(EapPacket):
    _eap_type = EapType.EAP_ONE_TIME_PASSWORD

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(eap_code: EapCode, frame: bytes, *args, **kwargs) -> 'EapOneTimePassword':
        raise NotImplementedError("Not yet implemented")


class EapGenericTokenCard(EapPacket):
    _eap_type = EapType.EAP_GENERIC_TOKEN_CARD

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(eap_code: EapCode, frame: bytes, *args, **kwargs) -> 'EapGenericTokenCard':
        raise NotImplementedError("Not yet implemented")


class EapTls(EapPacket):
    _eap_type = EapType.EAP_TLS

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(eap_code: EapCode, frame: bytes, *args, **kwargs) -> 'EapTls':
        raise NotImplementedError("Not yet implemented")


class EapTtls(EapPacket):
    _eap_type = EapType.EAP_TTLS

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(eap_code: EapCode, frame: bytes, *args, **kwargs) -> 'EapTtls':
        raise NotImplementedError("Not yet implemented")
