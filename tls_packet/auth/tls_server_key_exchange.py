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

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.security_params import TLSKeyExchangeTypes
from tls_packet.auth.tls import TLS, TLSv1_2
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import DecodeError, PARSE_ALL


class KeyExchangeAlgorithm(IntEnum):
    """
    """
    DHE_DSS = 1
    DHE_RSA = 2
    DH_ANON = 3
    RSA     = 4
    DH_DSS  = 5
    DH_RSA  = 6

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


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


class NamedCurve(IntEnum):
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
    X25519 = 29
    X488 = 30

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class ECPointsFormat(IntEnum):		# TODO: Move to own file

    UNCOMPRESSED = 0
    ANSIX962_COMPRESSED_PRIME = 1
    ANSIX962_COMPRESSED_CHAR2 = 2

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class TLSServerKeyExchange(TLSHandshake):
    """
    TLS Server Key Exchange Message

      This message will be sent immediately after the server Certificate
      message (or the ServerHello message, if this is an anonymous
      negotiation).

      The ServerKeyExchange message is sent by the server only when the
      server Certificate message (if sent) does not contain enough data
      to allow the client to exchange a pre-master secret.  This is true
      for the following key exchange methods:

         DHE_DSS
         DHE_RSA
         DH_anon

      It is not legal to send the ServerKeyExchange message for the
      following key exchange methods:

         RSA
         DH_DSS
         DH_RSA

      Other key exchange algorithms, such as those defined in [TLSECC],
      MUST specify whether the ServerKeyExchange message is sent or not;
      and if the message is sent, its contents.

          enum { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
                /* may be extended, e.g., for ECDH -- see [TLSECC - https://www.ietf.org/rfc/rfc5246.html#ref-TLSECC] */
               } KeyExchangeAlgorithm;

          struct {
              opaque dh_p<1..2^16-1>;
              opaque dh_g<1..2^16-1>;
              opaque dh_Ys<1..2^16-1>;
          } ServerDHParams;     /* Ephemeral DH parameters */

          dh_p
             The prime modulus used for the Diffie-Hellman operation.

          dh_g
             The generator used for the Diffie-Hellman operation.

          dh_Ys
             The server's Diffie-Hellman public value (g^X mod p).

           struct {
               select (KeyExchangeAlgorithm) {
                   case dh_anon:
                       ServerDHParams params;
                   case dhe_dss:
                   case dhe_rsa:
                       ServerDHParams params;
                       digitally-signed struct {
                           opaque client_random[32];
                           opaque server_random[32];
                           ServerDHParams params;
                       } signed_params;
                   case rsa:
                   case dh_dss:
                   case dh_rsa:
                       struct {} ;
                      /* message is omitted for rsa, dh_dss, and dh_rsa */
                   /* may be extended, e.g., for ECDH -- see [TLSECC] */
           } ServerKeyExchange;

        From RFC-8422 - https://www.ietf.org/rfc/rfc8422.html

           The ECCurveType enum used to have values for explicit prime and for
           explicit char2 curves.  Those values are now deprecated, so only one
           value remains:

           enum {
               deprecated (1..2),       # Was explicit_prime (1) and exxplicit_char2 (2)
               named_curve (3),
               reserved(248..255)
           } ECCurveType;

           struct {
               ECCurveType    curve_type;
               select (curve_type) {
                   case named_curve:
                       NamedCurve namedcurve;
               };
           } ECParameters;

       curve_type: This identifies the type of the elliptic curve domain
       parameters.

       namedCurve: Specifies a recommended set of elliptic curve domain
       parameters.  All those values of NamedCurve are allowed that refer to
       a curve capable of Diffie-Hellman.  With the deprecation of the
       explicit curves, this now includes all of the NamedCurve values.

               struct {
                   ECParameters    curve_params;
                   ECPoint         public;
               } ServerECDHParams;

       curve_params: Specifies the elliptic curve domain parameters
       associated with the ECDH public key.

       public: The ephemeral ECDH public key.

       The ServerKeyExchange message is extended as follows.

               enum {
                   ec_diffie_hellman
               } KeyExchangeAlgorithm;

       o  ec_diffie_hellman: Indicates the ServerKeyExchange message
          contains an ECDH public key.

          select (KeyExchangeAlgorithm) {
              case ec_diffie_hellman:
                  ServerECDHParams    params;
                  Signature           signed_params;
          } ServerKeyExchange;

       o  params: Specifies the ECDH public key and associated domain
          parameters.

       o  signed_params: A hash of the params, with the signature
          appropriate to that hash applied.  The private key corresponding
          to the certified public key in the server's Certificate message is
          used for signing.

            enum {
                ecdsa(3),
                ed25519(7)
                ed448(8)
            } SignatureAlgorithm;
            select (SignatureAlgorithm) {
               case ecdsa:
                    digitally-signed struct {
                        opaque sha_hash[sha_size];
                    };
               case ed25519,ed448:
                    digitally-signed struct {
                        opaque rawdata[rawdata_size];
                    };
            } Signature;
          ServerKeyExchange.signed_params.sha_hash
              SHA(ClientHello.random + ServerHello.random +
                                     ServerKeyExchange.params);
          ServerKeyExchange.signed_params.rawdata
              ClientHello.random + ServerHello.random +
                                     ServerKeyExchange.params;
    """

    def __init__(self, signature: bytes, key: bytes, server_params: bytes, *args, **kwargs):
        super().__init__(TLSHandshakeType.SERVER_KEY_EXCHANGE, *args, **kwargs)
        self._signature = signature
        self._server_params = server_params
        self._key = key

    @property
    def key(self) -> 'PublicKeyTypes':
        return self._key

    @property
    def signature(self) -> bytes:
        return self._signature

    def validate(self, client_random: bytes, server_random: bytes, signature_algorithm: 'TLSSignatureAlgorithm') -> bool:
        # Create the byte stream of the content to be verified by the signature. The parameters of
        # the message are octets 0, 1-2, and 3 which corresponds to the curve-type, named-curve,
        # and the public-key length. Then add the public key.  And of course our client/server random
        if self._signature:
            check_content = client_random + server_random + self._server_params
            return signature_algorithm.verify(self._signature, check_content)
        return True

    @staticmethod
    def parse(frame: bytes, *args,
              **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSServerKeyExchange """

        # type(1) + length(3) + remainder based on key algorithm
        required = 1 + 3
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSServerKeyExchange: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.SERVER_KEY_EXCHANGE:
            raise DecodeError(f"TLSServerKeyExchange: Message type is not SERVER_KEY_EXCHANGE. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')
        frame = frame[:msg_len + 4]  # Restrict the frame to only these bytes
        offset = 4

        security_params: SecurityParameters = kwargs.get('security_params')
        key_exchange_type = security_params.cipher_suite.key_exchange_type

        if frame_len - offset < msg_len:
            raise DecodeError(f"TLSServerKeyExchange: Key Exchange message truncated: Expected at least {msg_len} bytes, got: {frame_len - offset}")

        if key_exchange_type == TLSKeyExchangeTypes.RSA:
            return TLSServerKeyExchangeRSA.parse(frame[4:], *args, **kwargs)

        elif key_exchange_type == TLSKeyExchangeTypes.DHE:
            return TLSServerKeyExchangeDH.parse(frame[4:], *args, **kwargs)

        elif key_exchange_type == TLSKeyExchangeTypes.ECDHE:
            return TLSServerKeyExchangeECDH.parse(frame[4:], *args, **kwargs)

        else:
            raise DecodeError(f"Unsupported Key Exchange Type: {key_exchange_type}")

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")


class TLSServerKeyExchangeECDH(TLSServerKeyExchange):
    """
    ECDH TLS Server Key Exchange Message

      This message will be sent immediately after the server Certificate
      message (or the ServerHello message, if this is an anonymous
      negotiation).

        From RFC-8422 - https://www.ietf.org/rfc/rfc8422.html

           The ECCurveType enum used to have values for explicit prime and for
           explicit char2 curves.  Those values are now deprecated, so only one
           value remains:

           enum {
               deprecated (1..2),       # Was explicit_prime (1) and exxplicit_char2 (2)
               named_curve (3),
               reserved(248..255)
           } ECCurveType;

           struct {
               ECCurveType    curve_type;
               select (curve_type) {
                   case named_curve:
                       NamedCurve namedcurve;
               };
           } ECParameters;

       curve_type: This identifies the type of the elliptic curve domain
       parameters.

       namedCurve: Specifies a recommended set of elliptic curve domain
       parameters.  All those values of NamedCurve are allowed that refer to
       a curve capable of Diffie-Hellman.  With the deprecation of the
       explicit curves, this now includes all of the NamedCurve values.

               struct {
                   ECParameters    curve_params;
                   ECPoint         public;
               } ServerECDHParams;

       curve_params: Specifies the elliptic curve domain parameters
       associated with the ECDH public key.

       public: The ephemeral ECDH public key.

       The ServerKeyExchange message is extended as follows.

               enum {
                   ec_diffie_hellman
               } KeyExchangeAlgorithm;

       o  ec_diffie_hellman: Indicates the ServerKeyExchange message
          contains an ECDH public key.

          select (KeyExchangeAlgorithm) {
              case ec_diffie_hellman:
                  ServerECDHParams    params;
                  Signature           signed_params;
          } ServerKeyExchange;

       o  params: Specifies the ECDH public key and associated domain
          parameters.

       o  signed_params: A hash of the params, with the signature
          appropriate to that hash applied.  The private key corresponding
          to the certified public key in the server's Certificate message is
          used for signing.

            enum {
                ecdsa(3),
                ed25519(7)
                ed448(8)
            } SignatureAlgorithm;
            select (SignatureAlgorithm) {
               case ecdsa:
                    digitally-signed struct {
                        opaque sha_hash[sha_size];
                    };
               case ed25519,ed448:
                    digitally-signed struct {
                        opaque rawdata[rawdata_size];
                    };
            } Signature;

          ServerKeyExchange.signed_params.sha_hash
              SHA(ClientHello.random + ServerHello.random +
                                     ServerKeyExchange.params);
          ServerKeyExchange.signed_params.rawdata
              ClientHello.random + ServerHello.random +
                                     ServerKeyExchange.params;
    """
    def __init__(self, curve_type: ECCurveType, named_curve: NamedCurve,
                 public_key: bytes, signature: bytes, server_params: bytes, *args, **kwargs):
        super().__init__(signature, public_key, server_params, *args, **kwargs)

        if curve_type in (ECCurveType.EXPLICIT_PRIME, ECCurveType.EXPLICIT_CHAR2):
            # TODO: See if deprecated in TLSv1.1 or TLSv1.2 and add support if needed/requested
            raise DecodeError(f"TLSServerKeyExchange (ECDH): Curve type {curve_type} is deprecated")

        self._curve_type = curve_type
        self._named_curve = named_curve

    @property
    def curve_type(self) -> ECCurveType:
        return self._curve_type

    @property
    def named_curve(self) -> NamedCurve:
        return self._named_curve

    @staticmethod
    def parse(frame: bytes, *args,
              tls_version: Optional[TLS] = None,
              max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSServerKeyExchange """
        curve_type = ECCurveType(frame[0])
        named_curve = NamedCurve(struct.unpack_from("!H", frame, 1)[0])
        offset = 3
        pubkey_len = frame[offset]
        offset += 1

        if offset + pubkey_len + 2 > len(frame):
            raise DecodeError("TLSServerKeyExchange: message truncated. Unable to extract public key and/or signature length")

        pubkey = frame[offset:offset + pubkey_len]
        offset += pubkey_len

        sig_len = struct.unpack_from("!H", frame, offset)[0]
        offset += 2
        if offset + sig_len > len(frame):
            raise DecodeError("TLSServerKeyExchange: message truncated. Unable to extract signature")

        signature = frame[offset:offset + sig_len] if sig_len else b""
        print()
        print("Server Key Exchange Received:")
        print(f"  Curve Type : {curve_type}")
        print(f"  Named Curve: {named_curve}")
        print(f"  Pubkey     : ({pubkey_len}): {pubkey.hex()}")
        print(f"  Signature  : ({sig_len}): {signature.hex()}")
        print()

        # Create the key specific byte stream of the content to be verified by the signature. The parameters of
        # the message are octets 0, 1-2, and 3 which corresponds to the curve-type, named-curve,
        # and the public-key length.
        # struct {
        #   ECParameters curve_params;
        #   ECPoint public;
        # } ServerECDHParams;
        server_params = frame[0:4] + pubkey

        return TLSServerKeyExchangeECDH(curve_type, named_curve, pubkey, signature, server_params,
                                        *args, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")


class TLSServerKeyExchangeDH(TLSServerKeyExchange):

    def __init__(self, signature: bytes, server_params: bytes, *args, **kwargs):
        super().__init__(signature, server_params, *args, **kwargs)

    @staticmethod
    def parse(frame: bytes, *args,
              tls_version: Optional[TLS] = None,
              max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSServerKeyExchange """

        signature = b""
        server_params = b""
        return TLSServerKeyExchangeDH(signature, server_params, *args, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")


class TLSServerKeyExchangeRSA(TLSServerKeyExchange):

    def __init__(self, signature: bytes, server_params: bytes, *args, **kwargs):
        super().__init__(signature, server_params, *args, **kwargs)

    @staticmethod
    def parse(frame: bytes, *args,
              tls_version: Optional[TLS] = None,
              max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSServerKeyExchange """
        signature = b""
        server_params = b""
        return TLSServerKeyExchangeRSA(signature, server_params, *args, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")


TLSSupportedServerKeyExchange = {
    "TLSServerKeyExchangeECDH": TLSServerKeyExchangeECDH,
    "TLSServerKeyExchangeDH":   TLSServerKeyExchangeDH,
    "TLSServerKeyExchangeRSA":  TLSServerKeyExchangeRSA
}