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
from typing import Union, Optional, Iterable, Tuple, Set

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

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class EapType(IntEnum):
    EAP_NO_ALTERNATIVES = 0  # Used with EAP Legacy NAK to specify no alternative methods
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

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


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
        return self._msg_length if self._msg_length is not None else None

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

        code, eap_id, length = struct.unpack_from("!BBH", frame)

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

            print(f"EAPOL.parse: Before Decompression: {frame.hex()}")
            packet = frame_type.parse(frame, eap_id, length, *args, **kwargs)

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

            packet = parser.parse(frame, *args, **kwargs)

            if packet is None:
                raise DecodeError(f"Failed to decode EAPOL: {parser}")

            return packet

        except ValueError as e:
            raise DecodeError from e

    def pack(self, payload: Optional[bytes] = None) -> bytes:
        """ Convert to a packet for transmission """
        msg_len = self._msg_length or (len(payload) + 4) if payload else 4
        buffer = struct.pack("!BBH", self._eap_code, self._eap_id, msg_len)

        if payload:
            buffer += payload
        return buffer


class EapRequest(EAP):
    def __init__(self, eap_type: EapType, eap_type_data: Union['EapPacket', PacketPayload], **kwargs):
        super().__init__(EapCode.EAP_REQUEST, **kwargs)
        self._eap_type = EapType(eap_type)
        self._eap_type_data = eap_type_data  # TODO: Treat next in future as a layer

    @property
    def type_data(self) -> Union['EapPacket', PacketPayload]:
        return self._eap_type_data

    def pack(self, **argv) -> bytes:
        payload = self._eap_type_data.pack() if self._eap_type_data else b""
        return super().pack(payload=payload)

    @staticmethod
    def parse(frame: bytes, ident: int, length: int, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> 'EapRequest':
        offset = 4
        required = length

        if len(frame) < required:
            raise DecodeError(f"EapRequest: message truncated: Expected at least {required} bytes, got: {len(frame)}")

        eap_type = EapType(frame[offset])
        offset += 1
        payload_data = frame[offset: length]

        if max_depth > 0:
            # Parse the handshake message
            payload = EapRequest.parse_eap_type(eap_type, payload_data, *args, max_depth=max_depth-1, **kwargs)
        else:
            # Save it as blob data (note that we use the decompressed data)
            payload = PacketPayload(payload_data, *args, **kwargs)

        return EapRequest(eap_type, payload, length=length - 5, **kwargs)


class EapResponse(EAP):
    def __init__(self, eap_type: EapType, eap_type_data: Union['EapPacket', PacketPayload], **kwargs):
        super().__init__(EapCode.EAP_RESPONSE, **kwargs)
        self._eap_type = EapType(eap_type)
        self._eap_type_data = eap_type_data  # TODO: Treat next in future as a layer

    @property
    def type_data(self) -> Union['EapPacket', PacketPayload]:
        return self._eap_type_data

    def pack(self, **argv) -> bytes:
        payload = self._eap_type_data.pack() if self._eap_type_data else b""
        return super().pack(payload=payload)

    @staticmethod
    def parse(frame: bytes, ident: int, length: int, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union['EapResponse', None]:
        offset = 4
        required = length

        if len(frame) < required:
            raise DecodeError(f"EapResponse: message truncated: Expected at least {required} bytes, got: {len(frame)}")

        eap_type = EapType(frame[offset])
        offset += 1
        payload_data = frame[offset: length]

        if max_depth > 0:
            # Parse the handshake message
            payload = EapRequest.parse_eap_type(eap_type, payload_data, *args, max_depth=max_depth-1, **kwargs)
        else:
            # Save it as blob data (note that we use the decompressed data)
            payload = PacketPayload(payload_data, *args, **kwargs)

        return EapResponse(eap_type, payload, length=length - 5, **kwargs)


class EapSuccess(EAP):
    def __init__(self, **kwargs):
        super().__init__(EapCode.EAP_SUCCESS, **kwargs)

    @staticmethod
    def parse(frame: bytes, ident: int, length: int, *args, **kwargs) -> 'EapSuccess':
        return EapSuccess(eap_id=ident, length=length, **kwargs)


class EapFailure(EAP):
    def __init__(self, **kwargs):
        super().__init__(EapCode.EAP_FAILURE, **kwargs)

    @staticmethod
    def parse(frame: bytes, ident: int, length: int, *args, **kwargs) -> 'EapFailure':
        return EapFailure(eap_id=ident, length=length, **kwargs)


class EapInitiate(EAP):
    def __init__(self, **kwargs):
        super().__init__(EapCode.EAP_INITIATE, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, ident: int, length: int, *args, **kwargs) -> 'EapInitiate':
        raise NotImplementedError("Not yet implemented")


class EapFinish(EAP):
    def __init__(self, **kwargs):
        super().__init__(EapCode.EAP_FINISH, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, ident: int, length: int, *args, **kwargs) -> 'EapFinish':
        raise NotImplementedError("Not yet implemented")


class EapPacket(Packet):
    _eap_type = None

    @property
    def eap_type(self) -> EapType:
        return self._eap_type

    def pack(self, payload: Optional[bytes] = None) -> bytes:
        """ Convert to a packet for transmission """
        buffer = struct.pack("!B", self._eap_type) + (payload or b"")
        return super().pack(payload=buffer)


class EapIdentity(EapPacket):
    """
    The Identity Type is used to query the identity of the peer.
    Generally, the authenticator will issue this as the initial
    Request. An optional displayable message MAY be included to
    prompt the peer in the case where there is an expectation of
    interaction with a user. A Response of Type 1 (Identity) SHOULD
    be sent in Response to a Request with a Type of 1 (Identity).

    Some EAP implementations piggy-back various options into the
    Identity Request after a NUL-character. By default, an EAP
    implementation SHOULD NOT assume that an Identity Request or
    Response can be larger than 1020 octets.

    It is RECOMMENDED that the Identity Response be used primarily for
    routing purposes and selecting which EAP method to use. EAP
    Methods SHOULD include a method-specific mechanism for obtaining
    the identity, so that they do not have to rely on the Identity
    Response. Identity Requests and Responses are sent in cleartext,
    so an attacker may snoop on the identity, or even modify or spoof
    identity exchanges. To address these threats, it is preferable
    for an EAP method to include an identity exchange that supports
    per-packet authentication, integrity and replay protection, and
    confidentiality. The Identity Response may not be the appropriate
    identity for the method; it may have been truncated or obfuscated
    so as to provide privacy, or it may have been decorated for
    routing purposes. Where the peer is configured to only accept
    authentication methods supporting protected identity exchanges,
    the peer MAY provide an abbreviated Identity Response (such as
    omitting the peer-name portion of the NAI [RFC2486]). For further
    discussion of identity protection, see Section 7.3
    """
    _eap_type = EapType.EAP_IDENTITY

    def __init__(self, type_data: Optional[bytes] = None, **kwargs):
        super().__init__(**kwargs)
        self._type_data = type_data or b""

    @property
    def type_data(self) -> bytes:
        return self._type_data

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapIdentity':
        length = len(frame)

        if len(frame) < length:
            raise DecodeError(f"EapIdentity: message truncated: Expected at least {length} bytes, got: {len(frame)}")

        type_data = frame[:length]
        return EapIdentity(type_data, length=length, **kwargs)

    def pack(self) -> bytes:
        """ Convert to a packet for transmission """
        return super().pack(payload=self._type_data)


class EapLegacyNak(EapPacket):
    """
    The legacy Nak Type is valid only in Response messages. It is
    sent in reply to a Request where the desired authentication Type
    is unacceptable. Authentication Types are numbered 4 and above.
    The Response contains one or more authentication Types desired by
    the Peer. Type zero (0) is used to indicate that the sender has
    no viable alternatives, and therefore the authenticator SHOULD NOT
    send another Request after receiving a Nak Response containing a
    zero value.

    Since the legacy Nak Type is valid only in Responses and has very
    limited functionality, it MUST NOT be used as a general purpose
    error indication, such as for communication of error messages, or
    negotiation of parameters specific to a particular EAP method.
    """
    _eap_type = EapType.EAP_LEGACY_NAK
    _supported_auths = (EapType.EAP_NO_ALTERNATIVES, EapType.EAP_MD5_CHALLENGE, EapType.EAP_TLS)  # TODO: add others if neeeded

    def __init__(self, desired_auth: Optional[Union[EapType, Iterable[EapType]]] = (EapType.EAP_NO_ALTERNATIVES,), **kwargs):
        super().__init__(**kwargs)

        desired_auth = desired_auth or []
        if isinstance(desired_auth, EapType):
            desired_auth = [desired_auth]

        import sys
        print(f"Desired init: {desired_auth}", file=sys.stderr)

        for auth in desired_auth:
            if EapType(auth) not in self._supported_auths:
                raise NotImplementedError(f"EapLegacyNak: AuthType {auth} is not a supported desired Auth type")

        self._desired_auth: Set[EapType] = {EapType(auth) for auth in desired_auth}

    @property
    def desired_auth(self) -> Tuple[EapType]:
        import sys
        print(f"Desired: {self._desired_auth}", file=sys.stderr)
        return tuple(self._desired_auth)

    def pack(self, **argv) -> bytes:
        buffer = b""
        for auth in self._desired_auth:
            buffer += struct.pack("!B", auth.value)

        return super().pack(payload=buffer)

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapLegacyNak':
        length = len(frame)
        if len(frame) < length:
            raise DecodeError(f"EapLegacyNak: message truncated: Expected at least {length} bytes, got: {len(frame)}")

        desired_auth = {auth for auth in frame[:length]}

        return EapLegacyNak(desired_auth=desired_auth, length=length, **kwargs)


class EapMd5Challenge(EapPacket):
    """
    The MD5-Challenge Type is analogous to the PPP CHAP protocol
    [RFC1994] (with MD5 as the specified algorithm). The Request
    contains a "challenge" message to the peer. A Response MUST be
    sent in reply to the Request. The Response MAY be either of Type
    4 (MD5-Challenge), Nak (Type 3), or Expanded Nak (Type 254). The
    Nak reply indicates the peer’s desired authentication Type(s).
    EAP peer and EAP server implementations MUST support the MD5-
    Challenge mechanism. An authenticator that supports only passthrough
    MUST allow communication with a backend authentication
    server that is capable of supporting MD5-Challenge, although the
    EAP authenticator implementation need not support MD5-Challenge
    itself. However, if the EAP authenticator can be configured to
    authenticate peers locally (e.g., not operate in pass-through),
    then the requirement for support of the MD5-Challenge mechanism
    applies.

    Note that the use of the Identifier field in the MD5-Challenge
    Type is different from that described in [RFC1994]. EAP allows
    for retransmission of MD5-Challenge Request packets, while
    [RFC1994] states that both the Identifier and Challenge fields
    MUST change each time a Challenge (the CHAP equivalent of the
    MD5-Challenge Request packet) is sent.

    Note: [RFC1994] treats the shared secret as an octet string, and
    does not specify how it is entered into the system (or if it is
    handled by the user at all). EAP MD5-Challenge implementations
    MAY support entering passphrases with non-ASCII characters. See
    Section 5 for instructions how the input should be processed and
    encoded into octets.
    """
    _eap_type = EapType.EAP_MD5_CHALLENGE

    def __init__(self, challenge: Optional[bytes] = None, extra_data: Optional[bytes] = None, **kwargs):
        super().__init__(**kwargs)
        self._challenge = challenge or b""
        self._extra_data = extra_data or b""

    @property
    def challenge_len(self) -> int:
        return len(self._challenge) if self._challenge else 0

    @property
    def challenge(self) -> bytes:
        return self._challenge

    @property
    def extra_data(self) -> bytes:
        return self._extra_data

    def pack(self, **argv) -> bytes:
        buffer = struct.pack("!B", len(self._challenge)) + self._challenge + self._extra_data
        return super().pack(payload=buffer)

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapMd5Challenge':
        length = len(frame)

        if len(frame) < length:
            raise DecodeError(f"EapMd5Challenge: message truncated: Expected at least {length} bytes, got: {len(frame)}")

        challenge_length, = struct.unpack_from("!B", frame)

        if length - 1 < challenge_length:
            raise DecodeError(f"EapMd5Challenge: challenge truncated: Expected at least {challenge_length} bytes, got: {length - 1}")

        offset = 1
        challenge = frame[offset: offset + challenge_length]

        offset += challenge_length
        extra_data = frame[offset:]

        return EapMd5Challenge(challenge=challenge, extra_data=extra_data, length=length, **kwargs)


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
