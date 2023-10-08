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
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurve,
    SECP256R1,
    SECP384R1,
    SECP521R1)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from enum import IntEnum
from typing import Union, Optional

from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.security_params import TLSKeyExchangeTypes
from tls_packet.auth.tls import TLS, TLSv1_2
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import DecodeError, PARSE_ALL


class ECCurveType(IntEnum):
    """
    The ECCurveType enum used to have values for explicit prime and for
    explicit char2 curves.  Those values are now deprecated, so only one
    value remains:
       enum {
           deprecated (1..2),       # Was explicit_prime (1) and explicit_char2 (2)
           named_curve (3),
           reserved(248..255)
       } ECCurveType;
    """
    EXPLICIT_PRIME = 1  # Deprecated
    EXPLICIT_CHAR2 = 2  # Deprecated
    NAMED_CURVE = 3

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class ECPointsFormat(IntEnum):
    UNCOMPRESSED = 0
    ANSIX962_COMPRESSED_PRIME = 1
    ANSIX962_COMPRESSED_CHAR2 = 2

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class NamedCurveType(IntEnum):
    """
    RFC 4492 defined 25 different curves in the NamedCurve registry (now
    renamed the "TLS Supported Groups" registry, although the enumeration
    below is still named NamedCurve) for use in TLS.  Only three have
    seen much use.  This specification is deprecating the rest (with
    numbers 1-22).  This specification also deprecates the explicit
    curves with identifiers 0xFF01 and 0xFF02.  It also adds the new
    curves defined in [RFC7748].  The end result is as follows:

       enum {
           deprecated(1..22),
           secp256r1 (23), secp384r1 (24), secp521r1 (25),
           x25519(29), x448(30),
           reserved (0xFE00..0xFEFF),
           deprecated(0xFF01..0xFF02),
           (0xFFFF)
       } NamedCurve;
    """
    SECP256R1 = 23
    SECP384R1 = 24
    SECP521R1 = 25,
    X25519 = 29  # TODO: Not yet supported
    X488 = 30  # TODO: Not yet supported

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


# TODO: Cleanup and use 'EllipticCurve' when everything is working well
NamedCurve = EllipticCurve


def get_named_curve_by_type(code: NamedCurveType) -> EllipticCurve:
    class_impl = {
        NamedCurveType.SECP256R1: SECP256R1,
        NamedCurveType.SECP384R1: SECP384R1,
        NamedCurveType.SECP521R1: SECP521R1,
        # NamedCurveType.X25519:    X25519,
        # NamedCurveType.X488:      X488,
    }.get(code, None)

    return class_impl() if class_impl else None
