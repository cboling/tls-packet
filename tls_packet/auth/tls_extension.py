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
from typing import Union, Optional, Tuple, Any, List

from tls_packet.packet import DecodeError, PARSE_ALL
from tls_packet.packet import Packet


from tls_packet.auth.tls_server_key_exchange import ECCurveType, NamedCurve, ECPointsFormat


class TLSHelloExtensionType(IntEnum):
    """
    The TLSHelloExtensionType enum declares known Hello Extensions. Not all
    are supported at this time.

        enum {
            server_name(0),
            max_fragment_length(1),
            status_request(5),
            supported_groups(10),
            signature_algorithms(13),
            use_srtp(14),
            heartbeat(15),
            application_layer_protocol_negotiation(16), /* RFC 7301 */
            signed_certificate_timestamp(18),
            client_certificate_type(19),
            server_certificate_type(20),
            padding(21),
            pre_shared_key(41),
            early_data(42),
            supported_versions(43),
            cookie(44),
            psk_key_exchange_modes(45),
            certificate_authorities(47),
            oid_filters(48),
            post_handshake_auth(49),
            signature_algorithms_cert(50),
            key_share(51),
            (65535)
        } ExtensionType;

    """
    SERVER_NAME                            = 0   # [RFC6066][RFC9261]
    MAX_FRAGMENT_LENGTH                    = 1   # [RFC6066][RFC8449]
    CLIENT_CERTIFICATE_URL                 = 2   # [RFC6066]
    TRUSTED_CA_KEYS                        = 3   # [RFC6066]
    TRUNCATED_HMAC                         = 4   # [RFC6066][IESG Action 2018-08-16]
    STATUS_REQUEST                         = 5   # [RFC6066]
    USER_MAPPING                           = 6   # [RFC4681]
    CLIENT_AUTHZ                           = 7   # [RFC5878]
    SERVER_AUTHZ                           = 8   # [RFC5878]
    CERT_TYPE                              = 9   # [RFC6091]
    SUPPORTED_GROUPS                       = 10  # (renamed from "elliptic_curves") [RFC8422][RFC7919]
    EC_POINT_FORMATS                       = 11  # [RFC8422]
    SRP                                    = 12  # [RFC5054]
    SIGNATURE_ALGORITHMS                   = 13  # [RFC8446]
    USE_SRTP                               = 14  # [RFC5764]
    HEARTBEAT                              = 15  # [RFC6520]
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16  # [RFC7301]
    STATUS_REQUEST_V2                      = 17  # [RFC6961]
    SIGNED_CERTIFICATE_TIMESTAMP           = 18  # [RFC6962]
    CLIENT_CERTIFICATE_TYPE                = 19  # [RFC7250]
    SERVER_CERTIFICATE_TYPE                = 20  # [RFC7250]
    PADDING                                = 21  # [RFC7685]
    ENCRYPT_THEN_MAC                       = 22  # [RFC7366]
    EXTENDED_MASTER_SECRET                 = 23  # [RFC7627]
    TOKEN_BINDING                          = 24  # [RFC8472]
    CACHED_INFO                            = 25  # [RFC7924]
    TLS_LTS                                = 26  # [draft-gutmann-tls-lts]
    COMPRESS_CERTIFICATE                   = 27  # [RFC8879]
    RECORD_SIZE_LIMIT                      = 28  # [RFC8449]
    PWD_PROTECT                            = 29  # [RFC8492]
    PWD_CLEAR                              = 30  # [RFC8492]
    PASSWORD_SALT                          = 31  # [RFC8492]
    TICKET_PINNING                         = 32  # [RFC8672]
    TLS_CERT_WITH_EXTERN_PSK               = 33  # [RFC8773]
    DELEGATED_CREDENTIAL                   = 34  # [RFC9345]
    SESSION_TICKET                         = 35  # [RFC5077][RFC8447]
    TLMSP                                  = 36  # [ETSI TS 103 523-2]
    TLMSP_PROXYING                         = 37  # [ETSI TS 103 523-2]
    TLMSP_DELEGATE                         = 38  # [ETSI TS 103 523-2]
    SUPPORTED_EKT_CIPHERS                  = 39  # [RFC8870]
    PRE_SHARED_KEY                         = 41  # [RFC8446]
    EARLY_DATA                             = 42  # [RFC8446]
    SUPPORTED_VERSIONS                     = 43  # [RFC8446]
    COOKIE                                 = 44  # [RFC8446]
    PSK_KEY_EXCHANGE_MODES                 = 45  # [RFC8446]
    CERTIFICATE_AUTHORITIES                = 47  # [RFC8446]
    OID_FILTERS                            = 48  # [RFC8446]
    POST_HANDSHAKE_AUTH                    = 49  # [RFC8446]
    SIGNATURE_ALGORITHMS_CERT              = 50  # [RFC8446]
    KEY_SHARE                              = 51  # [RFC8446]
    TRANSPARENCY_INFO                      = 52  # [RFC9162]
    CONNECTION_ID_DEPRECATED               = 53  # [RFC9146](deprecated)
    CONNECTION_ID                          = 54  # [RFC9146]
    EXTERNAL_ID_HASH                       = 55  # [RFC8844]
    EXTERNAL_SESSION_ID                    = 56  # [RFC8844]
    QUIC_TRANSPORT_PARAMETERS              = 57  # [RFC9001]
    TICKET_REQUEST                         = 58  # [RFC9149]
    DNSSEC_CHAIN                           = 59  # [RFC9102][RFC Errata 6860]
    SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS  = 60  # [draft-pismenny-tls-dtls-plaintext-sequence-number-01]

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class TLSHelloExtension(Packet):
    """
    Hello Extensions

   A number of TLS messages contain tag-length-value encoded extensions
   structures.
        struct {
            ExtensionType extension_type;
            opaque extension_data<0..2^16-1>;
        } Extension;

        The table below indicates the messages where a given extension may
        appear, using the following notation: CH (ClientHello),
        SH (ServerHello), EE (EncryptedExtensions), CT (Certificate),
        CR (CertificateRequest), NST (NewSessionTicket), and
        HRR (HelloRetryRequest).  If an implementation receives an extension
        which it recognizes and which is not specified for the message in
        which it appears, it MUST abort the handshake with an
        "illegal_parameter" alert.

        +--------------------------------------------------+-------------+
        | Extension                                        | TLS 1.3     |
        +--------------------------------------------------+-------------+
        | server_name [RFC6066]                            | CH, EE      |
        | max_fragment_length [RFC6066]                    | CH, EE      |
        | status_request [RFC6066]                         | CH, CR, CT  |
        | supported_groups [RFC7919]                       | CH, EE      |
        | signature_algorithms (RFC 8446)                  | CH, CR      |
        | use_srtp [RFC5764]                               | CH, EE      |
        | heartbeat [RFC6520]                              | CH, EE      |
        | application_layer_protocol_negotiation [RFC7301] | CH, EE      |
        | signed_certificate_timestamp [RFC6962]           | CH, CR, CT  |
        | client_certificate_type [RFC7250]                | CH, EE      |
        | server_certificate_type [RFC7250]                | CH, EE      |
        | padding [RFC7685]                                | CH          |
        | key_share (RFC 8446)                             | CH, SH, HRR |
        | pre_shared_key (RFC 8446)                        | CH, SH      |
        | psk_key_exchange_modes (RFC 8446)                | CH          |
        | early_data (RFC 8446)                            | CH, EE, NST |
        | cookie (RFC 8446)                                | CH, HRR     |
        | supported_versions (RFC 8446)                    | CH, SH, HRR |
        | certificate_authorities (RFC 8446)               | CH, CR      |
        | oid_filters (RFC 8446)                           | CR          |
        | post_handshake_auth (RFC 8446)                   | CH          |
        | signature_algorithms_cert (RFC 8446)             |  CH, CR     |
        +--------------------------------------------------+-------------+

       struct {
           ExtensionType extension_type;
           opaque extension_data<0..2^16-1>;
       } Extension;

       enum {
           signature_algorithms(13), (65535)
       } ExtensionType;

       enum{
           none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
           sha512(6), (255)
       } HashAlgorithm;
       enum {
          anonymous(0), rsa(1), dsa(2), ecdsa(3), (255)
       } SignatureAlgorithm;

       struct {
             HashAlgorithm hash;
             SignatureAlgorithm signature;
       } SignatureAndHashAlgorithm;

       SignatureAndHashAlgorithm
        supported_signature_algorithms<2..2^16-1>;
    """
    def __init__(self, exten_type: TLSHelloExtensionType,
                 length: Optional[Union[int, None]] = None,
                 session: Optional[Union['TLSClient', 'TLSServer']] = None, **kwargs):
        super().__init__(**kwargs)
        self._session = session
        self._exten_type = TLSHelloExtensionType(exten_type)
        self._msg_length = length

    def __repr__(self):
        return f"{self.__class__.__qualname__}: Type: {self._exten_type}, Len: {self._msg_length}"

    @property
    def length(self) -> int:
        return self._msg_length

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> List["TLSHelloExtension"]:
        if frame is None:
            raise DecodeError("TLSHelloExtension.parse: Called with frame = None")

        frame_len = len(frame)
        if frame_len < 4:
            raise DecodeError(f"TLSHelloExtension: header truncated, need minimum of 4 bytes, found: {frame_len}")

        extensions = []
        try:
            while len(frame) > 0:
                extension_type, length = struct.unpack_from("!HH", frame)
                if frame_len - 2 < length:
                    raise DecodeError(f"TLSHelloExtension: Extension truncated, need minimum of {length} bytes, found: {frame_len - 2}")

                parser = {
                    # TLSHelloExtensionType.SERVER_NAME:                            TlSxxxExtension,
                    # TLSHelloExtensionType.SERVER_NAME:                            TLSxxxExtension,
                    # TLSHelloExtensionType.MAX_FRAGMENT_LENGTH:                    TLSxxxExtension,
                    # TLSHelloExtensionType.CLIENT_CERTIFICATE_URL:                 TLSxxxExtension,
                    # TLSHelloExtensionType.TRUSTED_CA_KEYS:                        TLSxxxExtension,
                    # TLSHelloExtensionType.TRUNCATED_HMAC:                         TLSxxxExtension,
                    # TLSHelloExtensionType.STATUS_REQUEST:                         TLSxxxExtension,
                    # TLSHelloExtensionType.USER_MAPPING:                           TLSxxxExtension,
                    # TLSHelloExtensionType.CLIENT_AUTHZ:                           TLSxxxExtension,
                    # TLSHelloExtensionType.SERVER_AUTHZ:                           TLSxxxExtension,
                    # TLSHelloExtensionType.CERT_TYPE:                              TLSxxxExtension,
                    TLSHelloExtensionType.SUPPORTED_GROUPS:                       TLSSupportedGroupsExtension,     # Also known as Elliptic Curves
                    TLSHelloExtensionType.EC_POINT_FORMATS:                       TLSECPointsFormatExtension,
                    # TLSHelloExtensionType.SRP:                                    TLSxxxExtension,
                    #TLSHelloExtensionType.SIGNATURE_ALGORITHMS:                   TLSSignatureAlgorithmsExtension,
                    # TLSHelloExtensionType.USE_SRTP:                               TLSxxxExtension,
                    # TLSHelloExtensionType.HEARTBEAT:                              TLSxxxExtension,
                    # TLSHelloExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION: TLSxxxExtension,
                    # TLSHelloExtensionType.STATUS_REQUEST_V2:                      TLSxxxExtension,
                    # TLSHelloExtensionType.SIGNED_CERTIFICATE_TIMESTAMP:           TLSxxxExtension,
                    # TLSHelloExtensionType.CLIENT_CERTIFICATE_TYPE:                TLSxxxExtension,
                    # TLSHelloExtensionType.SERVER_CERTIFICATE_TYPE:                TLSxxxExtension,
                    # TLSHelloExtensionType.PADDING:                                TLSxxxExtension,
                    #TLSHelloExtensionType.ENCRYPT_THEN_MAC:                       TLSEncryptThenMacExtension,
                    #TLSHelloExtensionType.EXTENDED_MASTER_SECRET:                 TLSExtendedMasterSecretExtension,
                    # TLSHelloExtensionType.TOKEN_BINDING:                          TLSxxxExtension,
                    # TLSHelloExtensionType.CACHED_INFO:                            TLSxxxExtension,
                    # TLSHelloExtensionType.TLS_LTS:                                TLSxxxExtension,
                    # TLSHelloExtensionType.COMPRESS_CERTIFICATE:                   TLSxxxExtension,
                    # TLSHelloExtensionType.RECORD_SIZE_LIMIT:                      TLSxxxExtension,
                    # TLSHelloExtensionType.PWD_PROTECT:                            TLSxxxExtension,
                    # TLSHelloExtensionType.PWD_CLEAR:                              TLSxxxExtension,
                    # TLSHelloExtensionType.PASSWORD_SALT:                          TLSxxxExtension,
                    # TLSHelloExtensionType.TICKET_PINNING:                         TLSxxxExtension,
                    # TLSHelloExtensionType.TLS_CERT_WITH_EXTERN_PSK:               TLSxxxExtension,
                    # TLSHelloExtensionType.DELEGATED_CREDENTIAL:                   TLSxxxExtension,
                    # TLSHelloExtensionType.SESSION_TICKET:                         TLSxxxExtension,
                    # TLSHelloExtensionType.TLMSP:                                  TLSxxxExtension,
                    # TLSHelloExtensionType.TLMSP_PROXYING:                         TLSxxxExtension,
                    # TLSHelloExtensionType.TLMSP_DELEGATE:                         TLSxxxExtension,
                    # TLSHelloExtensionType.SUPPORTED_EKT_CIPHERS:                  TLSxxxExtension,
                    # TLSHelloExtensionType.PRE_SHARED_KEY:                         TLSxxxExtension,
                    # TLSHelloExtensionType.EARLY_DATA:                             TLSxxxExtension,
                    # TLSHelloExtensionType.SUPPORTED_VERSIONS:                     TLSxxxExtension,
                    # TLSHelloExtensionType.COOKIE:                                 TLSxxxExtension,
                    # TLSHelloExtensionType.PSK_KEY_EXCHANGE_MODES:                 TLSxxxExtension,
                    # TLSHelloExtensionType.CERTIFICATE_AUTHORITIES:                TLSxxxExtension,
                    # TLSHelloExtensionType.OID_FILTERS:                            TLSxxxExtension,
                    # TLSHelloExtensionType.POST_HANDSHAKE_AUTH:                    TLSxxxExtension,
                    # TLSHelloExtensionType.SIGNATURE_ALGORITHMS_CERT:              TLSxxxExtension,
                    # TLSHelloExtensionType.KEY_SHARE:                              TLSxxxExtension,
                    # TLSHelloExtensionType.TRANSPARENCY_INFO:                      TLSxxxExtension,
                    # TLSHelloExtensionType.CONNECTION_ID_DEPRECATED:               TLSxxxExtension,
                    # TLSHelloExtensionType.CONNECTION_ID:                          TLSxxxExtension,
                    # TLSHelloExtensionType.EXTERNAL_ID_HASH:                       TLSxxxExtension,
                    # TLSHelloExtensionType.EXTERNAL_SESSION_ID:                    TLSxxxExtension,
                    # TLSHelloExtensionType.QUIC_TRANSPORT_PARAMETERS:              TLSxxxExtension,
                    # TLSHelloExtensionType.TICKET_REQUEST:                         TLSxxxExtension,
                    # TLSHelloExtensionType.DNSSEC_CHAIN:                           TLSxxxExtension,
                    # TLSHelloExtensionType.SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS:  TLSxxxExtension,
                }.get(extension_type)

                if parser is not None:
                    extension = parser.parse(frame, *args, **kwargs)
                else:
                    extension = TLSUnsupportedHelloExtension(extension_type, frame[4:], *args, length=length, **kwargs)

                if extension is None:
                    DecodeError(f"Failed to decode TLSHelloExtension. {len} extensions decoded so far and remaining frame length was {len(frame)}")

                extensions.append(extension)
                extension_len = extension.length + 4        # 2 bytes for the extn-type and 2 bytes for length field
                frame = frame[extension_len:]
                print(f"TLSHelloExtension: Saved extension to list: {extension}")
                print(f"TLSHelloExtension: {len(frame)} bytes remaining")
                print(f"TLSHelloExtension: Remaining frame: {frame.hex()}")

            return extensions

        except ValueError as e:
            raise DecodeError from e

    def pack(self, payload: Optional[bytes] = b'') -> bytes:        # TODO: make all pack 'payload' default to b''
        """ Convert to a packet for transmission """
        return struct.pack("!HH", self._exten_type, self._msg_length) + payload


class TLSUnsupportedHelloExtension(TLSHelloExtension):
    """
    Helper class to bundle all extensions that are not fully supported
    """
    def __init__(self, exten_type: TLSHelloExtensionType, payload: bytes, *args, **kwargs):
        super().__init__(exten_type, *args, **kwargs)
        self._payload = payload

    def __repr__(self):
        return super().__repr__() + f", Payload Length: {len(self._payload)}"

    def pack(self, payload: Optional[bytes] = b'') -> bytes:
        return super().pack(self._payload)

    def __eq__(self, other: Any) -> bool:
        """ Are two layers identical in content """
        return self._original_frame == bytes(other)


class TLSSupportedGroupsExtension(TLSHelloExtension):
    """
    TLSSupportedGroupsExtension  (renamed from "elliptic_curves") [RFC8422] [RFC7919]
    """
    def __init__(self, *args, supported_groups: Optional[List[int]] = None, **kwargs):
        super().__init__(TLSHelloExtensionType.SUPPORTED_GROUPS, *args, **kwargs)
        self._supported_groups = supported_groups or []

    def __repr__(self):
        return super().__repr__() + f", Supported Groups: [{', '.join(self._supported_groups)}]"

    @property
    def supported_groups(self) -> Tuple[int]:
        return tuple(self._supported_groups)

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union['TLSSupportedGroupsExtension', None]:
        required = 2
        extn_data_len = len(frame) - 4 - required

        if extn_data_len < required:
            raise DecodeError(f"TLSSupportedGroupsExtension: Extension truncated: Expected at least {required} bytes, got: {extn_data_len}")

        extn_type, _, extn_len = struct.unpack_from("!HHH", frame)
        if extn_type != TLSHelloExtensionType.SUPPORTED_GROUPS:
            raise DecodeError(f"TLSSupportedGroupsExtension: Extension type is not SUPPORTED_GROUPS. Found: {extn_type}")

        if extn_len & 1:
            raise DecodeError(f"TLSSupportedGroupsExtension: Extension truncated: Even number of bytes expected, got: {extn_data_len}")

        frame = frame[6:]
        if len(frame) < extn_len:
            raise DecodeError(f"TLSSupportedGroupsExtension: Extension truncated: Expected at least {extn_len} bytes, got: {len(frame)}")

        supported_groups = [int.from_bytes(frame[offset:offset + 2], 'big') for offset in range(0, extn_len, 2)]

        return TLSSupportedGroupsExtension(supported_groups=supported_groups, *args, **kwargs)

    def pack(self,  payload: Optional[bytes] = b'') -> bytes:
        buffer = struct.pack("!H", len(self._supported_groups) * 2)
        for group in self._supported_groups:
            buffer += struct.pack("!H", group)

        return super().pack(buffer)


class TLSECPointsFormatExtension(TLSHelloExtension):
    """
    TLSECPointsFormatExtension   [RFC8422]
    """
    def __init__(self, *args, formats: Optional[List[ECPointsFormat]] = None, **kwargs):
        super().__init__(TLSHelloExtensionType.EC_POINT_FORMATS, *args, **kwargs)
        self._formats = formats or []

    def __repr__(self):
        return super().__repr__() + f", Formats: [{', '.join(self._formats)}]"

    @property
    def formats(self) -> Tuple[int]:
        return tuple(self._formats)

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union['TLSECPointsFormatExtension', None]:
        required = 1
        extn_data_len = len(frame) - 4 - required

        if extn_data_len < required:
            raise DecodeError(f"TLSECPointsFormatExtension: Extension truncated: Expected at least {required} bytes, got: {extn_data_len}")

        extn_type, _, extn_len = struct.unpack_from("!HHB", frame)
        if extn_type != TLSHelloExtensionType.EC_POINT_FORMATS:
            raise DecodeError(f"TLSECPointsFormatExtension: Extension type is not EC_POINT_FORMATS. Found: {extn_type}")

        frame = frame[5:]
        if len(frame) < extn_len:
            raise DecodeError(f"TLSECPointsFormatExtension: Extension truncated: Expected at least {extn_len} bytes, got: {len(frame)}")

        formats = [ECPointsFormat(frame[offset]) for offset in range(0, extn_len)]

        return TLSECPointsFormatExtension(formats=formats, *args, **kwargs)

    def pack(self,  payload: Optional[bytes] = b'') -> bytes:
        buffer = struct.pack("!b", len(self._formats))
        for ec_format in self._formats:
            buffer += ec_format

        return super().pack(buffer)


class TLSSignatureAlgorithmsExtension(TLSHelloExtension):
    """
    TLSSignatureAlgorithmsExtension   [RFC8446]
    """
    pass


class TLSEncryptThenMacExtension(TLSHelloExtension):
    """
    TLSEncryptThenMacExtension   [RFC7366]
    """
    pass


class TLSExtendedMasterSecretExtension(TLSHelloExtension):
    """
    TLSExtendedMasterSecretExtension   [RFC7627]
    """
    pass

