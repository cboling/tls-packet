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

from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import DecodeError, PARSE_ALL


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

    def __init__(self, curve_type: [ECCurveType], named_curve: [NamedCurve],
                 public_key: bytes, signature: bytes, *args, **kwargs):
        super().__init__(TLSHandshakeType.SERVER_KEY_EXCHANGE, *args, **kwargs)

        self._curve_type = curve_type
        self._named_curve = named_curve
        self._public_key = public_key
        self._signature = signature

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSServerKeyExchange """

        # type(1) + length(3) + curve_type(1) + named_curve(2) + pubkey len (1) + pubkey (0..n) + signature len (2) + signature (0..n)
        required = 1 + 3 + 1 + 2 + 1 + 2
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSServerKeyExchange: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.SERVER_KEY_EXCHANGE:
            raise DecodeError(f"TLSServerKeyExchange: Message type is not SERVER_KEY_EXCHANGE. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')
        frame = frame[:msg_len + 4]  # Restrict the frame to only these bytes

        curve_type = ECCurveType(frame[4])
        named_curve = NamedCurve(struct.unpack_from("!H", frame, 5)[0])

        pubkey_len = frame[7]
        offset = 8
        if offset + pubkey_len + 2 > len(frame):
            raise DecodeError("TLSServerKeyExchange: message truncated. Unable to extract public key and/or signature length")

        pubkey = frame[offset:offset + pubkey_len]
        offset += pubkey_len

        sig_len = struct.unpack_from("!H", frame, offset)[0]
        offset += 2
        if offset + sig_len > len(frame):
            raise DecodeError("TLSServerKeyExchange: message truncated. Unable to extract signature")

        signature = frame[offset:offset + sig_len]

        return TLSServerKeyExchange(curve_type, named_curve, pubkey, signature, *args, length=msg_len, original_frame=frame, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
