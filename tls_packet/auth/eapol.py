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
from tls_packet.auth.eap import EAP


class EAPOLPacketType(IntEnum):
    """
    This field is one octet in length. Table 11-3 lists the Packet Types specified by this standard, clause(s) that
    specify Packet Body encoding, decoding, and validation for each type, and the protocol entities that are the
    intended recipients. All other possible values of the Packet Type shall not be used: they are reserved for
    future extensions. To ensure that backward compatibility is maintained for future versions, validation, and
    protocol version handling for all types of EAPOL PDUs shall follow certain general rules (11.4, 11.5).
    """
    EAPOL_EAP = 0
    EAPOL_START = 1
    EAPOL_LOGOFF = 2
    EAPOL_KEY = 3
    EAPOL_ENCAPSULATED_ASF_ALERT = 4
    EAPOL_MKA = 5
    EAPOL_ANNOUNCMENT_GENERIC = 6
    EAPOL_ANNOUNCMENT_SPECIFIC = 7
    EAPOL_ANNOUNCMENT_REQ = 8

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


class EAPOL(Packet):
    """
    EAPOL Packet Class

       struct {
           ContentType type;
           ProtocolVersion version;
           uint16 length;
        ... type specific data here
    """
    def __init__(self, packet_type: EAPOLPacketType, length: [int] = None, version: Optional[int] = 2, **kwargs):

        super().__init__(**kwargs)
        self._version = version
        self._packet_type = EAPOLPacketType(packet_type)
        self._msg_length = length

        if not 1 <= self._version <= 3:
            raise ValueError(f"EAPOL: Invalid protocol version: {version}, must be 1..3")

        if self._version != 1:
            raise NotImplementedError(f"TODO: Only version 2 supported at this time")

    def __repr__(self):
        return f"{self.__class__.__qualname__}: Type: {self._packet_type}(v{self._version}), Len: {self._msg_length}"

    @staticmethod
    def EtherType() -> int:
        return 0x888e

    @property
    def length(self) -> int:
        return self._msg_length if self._msg_length is not None else len(bytes(self))

    @property
    def packet_type(self) -> EAPOLPacketType:
        return self._packet_type

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EAPOL':
        """
        """
        if frame is None:
            raise DecodeError("EAPOL.parse: Called with frame = None")

        if len(frame) < 4:
            raise DecodeError(f"EAPOL: header truncated, need minimum of 4 bytes, found: {len(frame)}")

        version, msg_type, length = struct.unpack_from("!BBH", frame)

        try:
            msg_type = EAPOLPacketType(msg_type)
            frame_type = {
                EAPOLPacketType.EAPOL_EAP:                    EapolEAP,
                EAPOLPacketType.EAPOL_START:                  EapolStart,
                EAPOLPacketType.EAPOL_LOGOFF:                 EapolLogoff,
                EAPOLPacketType.EAPOL_KEY:                    EapolKey,
                EAPOLPacketType.EAPOL_ENCAPSULATED_ASF_ALERT: EapolEncapsulatedAsfAlert,
                EAPOLPacketType.EAPOL_MKA:                    EapolMKA,
                EAPOLPacketType.EAPOL_ANNOUNCMENT_GENERIC:    EapolAnnouncementGeneric,
                EAPOLPacketType.EAPOL_ANNOUNCMENT_SPECIFIC:   EapolAnnouncementSpecific,
                EAPOLPacketType.EAPOL_ANNOUNCMENT_REQ:        EapolAnnouncementSpecific,
            }.get(msg_type)

            print(f"EAPOL:parse. Before Decompression: {frame.hex()}")
            packet = frame_type.parse(frame, *args, version=version, length=length, **kwargs)

            if packet is None:
                raise DecodeError(f"Failed to decode EAPOL: {frame_type}")

            return packet

        except ValueError as e:
            raise DecodeError from e

    def pack(self, payload: Optional[bytes] = None) -> bytes:
        """ Convert to a packet for transmission """
        msg_len = len(payload) if payload else 0
        buffer = struct.pack("!BBH", self._version, self._packet_type, msg_len)

        if payload:
            buffer += payload
        return buffer


class EapolEAP(EAPOL):
    """
    The Packet Body of each EAPOL PDU with a Packet Type of EAPOL-EAP encapsulates exactly one EAP
    packet
    """
    def __init__(self, eap: Optional[Union[EAP, PacketPayload]] = None, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_EAP, **kwargs)
        # TODO: Treat next in future as a layer
        self.m_eap = eap

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> 'EapolEAP':
        required = 4 + 4

        if len(frame) < required:
            raise DecodeError(f"EapolEAP: message truncated: Expected at least {required} bytes, got: {len(frame)}")

        version, msg_type, length = struct.unpack_from("!BBH", frame)
        if msg_type != EAPOLPacketType.EAPOL_EAP:
            raise DecodeError(f"EapolEAP: Message type is not EAPOL_EAP. Found: {msg_type}")

        offset = 4
        required = offset + length

        if len(frame) < required:
            raise DecodeError(f"EapolEAP: message EAP payload truncated: Expected at least {required} bytes, got: {len(frame)}")

        payload_data = frame[offset:required]
        if max_depth > 0:
            # Parse the handshake message
            payload = EAP.parse(payload_data, *args, max_depth=max_depth-1, **kwargs)
        else:
            # Save it as blob data (note that we use the decompressed data)
            payload = PacketPayload(payload_data, *args, **kwargs)

        return EapolEAP(eap=payload, version=version, **kwargs)


class EapolStart(EAPOL):
    """
    Version 2 and earlier EAPOL-Start PDUs are transmitted with no Packet Body. Consistent with the protocol
    versioning rules (11.5), EAPOL PDUs with this Packet Type and EAP Protocol Versions are processed as
    normal even if they contain a Packet Body. Both the contents of the Packet Body Length field, and the
    contents of any Packet Body or subsequent octets are ignored.

    EAPOL-Start PDUs with Protocol Version of 3 can be transmitted with or without a Packet Body. If bit 1
    (the least significant bit) of the first octet of the Packet Body of is set, receipt of the PDU solicits an
    announcement. The other bits in this initial octet, shall be transmitted as 0 and ignored on receipt. The
    remaining octets (if any) of the Packet Body encode TLVs, using the format and type codes specified for
    EAPOL-Announcements (11.12, Table 11-8), to convey information for the authenticator to use (and to
    provide to other back end services) to apply authorization and other policies.
    """
    def __init__(self, tlvs: Optional[List[Any]] = None, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_START, **kwargs)
        self._tlvs = tlvs or []

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapolStart':
        required = 4

        if len(frame) < required:
            raise DecodeError(f"EapolStart: message truncated: Expected at least {required} bytes, got: {len(frame)}")

        version, msg_type, length = struct.unpack_from("!BBH", frame)
        if msg_type != EAPOLPacketType.EAPOL_EAP:
            raise DecodeError(f"EapolStart: Message type is not EAPOL_Start. Found: {msg_type}")

        tlvs = None
        if version >= 3 and length > 0:
            # TODO: Support when needed
            raise NotImplementedError("TODO: not yet implemented")

        return EapolStart(tlvs=tlvs, version=version, **kwargs)


class EapolLogoff(EAPOL):
    def __init__(self, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_LOGOFF, **kwargs)

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapolLogoff':
        required = 4

        if len(frame) < required:
            raise DecodeError(f"EapolLogoff: message truncated: Expected at least {required} bytes, got: {len(frame)}")

        version, msg_type, length = struct.unpack_from("!BBH", frame)
        if msg_type != EAPOLPacketType.EAPOL_EAP:
            raise DecodeError(f"EapolLogoff: Message type is not EAPOL_Start. Found: {msg_type}")

        if length > 0:
            raise DecodeError(f"EapolLogoff: message payload length should be 0, found: {length}")

        return EapolLogoff(version=version, **kwargs)


class EapolKey(EAPOL):
    def __init__(self, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_Key, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapolKey':
        raise NotImplementedError("Not yet implemented")


class EapolEncapsulatedAsfAlert(EAPOL):
    def __init__(self, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_ENCAPSULATED_ASF_ALERT, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> Union['EapolEncapsulatedAsfAlert', None]:
        raise NotImplementedError("Not yet implemented")


class EapolMKA(EAPOL):
    def __init__(self, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_MKA, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapolMKA':
        raise NotImplementedError("Not yet implemented")


class EapolAnnouncementGeneric(EAPOL):
    def __init__(self, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_ANNOUNCMENT_GENERIC, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> Union['EapolAnnouncementGeneric', None]:
        raise NotImplementedError("Not yet implemented")


class EapolAnnouncementSpecific(EAPOL):
    def __init__(self, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_ANNOUNCMENT_SPECIFIC, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapolAnnouncementSpecific':
        raise NotImplementedError("Not yet implemented")


class EapolAnnouncmentReq(EAPOL):
    def __init__(self, **kwargs):
        super().__init__(EAPOLPacketType.EAPOL_ANNOUNCMENT_REQ, **kwargs)
        raise NotImplementedError("Not yet implemented")

    def pack(self, **argv) -> bytes:
        raise NotImplementedError("Not yet implemented")

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> 'EapolAnnouncmentReq':
        raise NotImplementedError("Not yet implemented")
