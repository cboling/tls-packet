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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.x509 import Certificate
from enum import IntEnum
from typing import Union, Optional, Tuple

from tls_packet.auth.master_secret import RSAPreMasterSecret
from tls_packet.auth.master_secret import RSAPreMasterSecret, ClientDiffieHellmanPublic
from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.security_params import TLSKeyExchangeTypes
from tls_packet.auth.tls import TLS, TLSv1_2
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_named_curve import get_named_curve_by_type
from tls_packet.auth.tls_server_key_exchange import NamedCurveType
from tls_packet.packet import PARSE_ALL


class TLSClientKeyEncoding(IntEnum):
    """
    Encoding type of client key

        The encoding in the message is implied by the protocol and this is mainly to help
        with debugging and output
    """
    UNKNOWN = 0
    RSA_PREMASTER_SECRET = 1                # RSAPreMasterSecret
    CLIENT_DIFFIE_HELLMAN_PUBLIC = 2        # ClientDiffieHellmanPublic

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


class TLSClientKeyExchange(TLSHandshake):
    """
    Client Key Exchange Message

      This message is always sent by the client.  It MUST immediately
      follow the client certificate message, if it is sent.  Otherwise,
      it MUST be the first message sent by the client after it receives
      the ServerHelloDone message.

      With this message, the premaster secret is set, either by direct
      transmission of the RSA-encrypted secret or by the transmission of
      Diffie-Hellman parameters that will allow each side to agree upon
      the same premaster secret.

      When the client is using an ephemeral Diffie-Hellman exponent,
      then this message contains the client's Diffie-Hellman public
      value.  If the client is sending a certificate containing a static
      DH exponent (i.e., it is doing fixed_dh client authentication),
      then this message MUST be sent but MUST be empty.

      The choice of messages depends on which key exchange method has
      been selected.  See Section 7.4.3 for the KeyExchangeAlgorithm
      definition.

          struct {
              select (KeyExchangeAlgorithm) {
                  case rsa:
                      EncryptedPreMasterSecret;
                  case dhe_dss:
                  case dhe_rsa:
                  case dh_dss:
                  case dh_rsa:
                  case dh_anon:
                      ClientDiffieHellmanPublic;
                  case ecdhe_ecdsa:
                  case ecdhe_rsa:
                  case ecdhe_anon:
                      ClientECDiffeHellmanPublic;       # See RFC8422
              } exchange_keys;
    """

    def __init__(self, security_params: Optional[SecurityParameters] = None,
                 key: Optional[Union[RSAPreMasterSecret, ClientDiffieHellmanPublic, bytes]] = None,
                 client_hello_tls_version: Optional[TLS] = None,
                 **kwargs):

        super().__init__(TLSHandshakeType.CLIENT_KEY_EXCHANGE, **kwargs)
        self._security_params = security_params
        self._client_hello_tls_version = client_hello_tls_version
        self._key = key

    @property
    def key(self) -> Union[RSAPreMasterSecret, ClientDiffieHellmanPublic]:
        return self._key

    @property
    def server_public_key(self) -> PublicKeyTypes:
        return self._security_params.server_public_key

    @property
    def client_random(self) -> bytes:
        return self._security_params.client_random

    @property
    def server_random(self) -> bytes:
        return self._security_params.server_random

    @staticmethod
    def parse(frame: bytes, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")

    def generate(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError("Implement in derive class")

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        if self._key:
            key_buffer = bytes(self._key)
            return super().pack(payload=key_buffer)

        pre_master_secret, encrypted_pre_master_secret = self.generate()
        # TODO: Save off pre_master_secret

        return super().pack(payload=encrypted_pre_master_secret)
        # key_buffer = bytes(self._key)
        # return super().pack(payload=key_buffer)

    @staticmethod
    def create(tls_client: 'TLSCLient', **kwargs) -> 'TLSClientKeyExchange':
        """
        For all key exchange methods, the same algorithm is used to convert
        the pre_master_secret into the master_secret.  The pre_master_secret
        should be deleted from memory once the master_secret has been
        computed.

          master_secret = PRF(pre_master_secret, "master secret",
                              ClientHello.random + ServerHello.random)
                              [0..47];

        The master secret is always exactly 48 bytes in length.  The length
        of the premaster secret will vary depending on key exchange method.

        RSA

           When RSA is used for server authentication and key exchange, a 48-
           byte pre_master_secret is generated by the client, encrypted under
           the server's public key, and sent to the server.  The server uses its
           private key to decrypt the pre_master_secret.  Both parties then
           convert the pre_master_secret into the master_secret, as specified
           above.

        Diffie-Hellman

           A conventional Diffie-Hellman computation is performed.  The
           negotiated key (Z) is used as the pre_master_secret, and is converted
           into the master_secret, as specified above.  Leading bytes of Z that
           contain all zero bits are stripped before it is used as the
           pre_master_secret.

           Note: Diffie-Hellman parameters are specified by the server and may
           be either ephemeral or contained within the server's certificate.
        """
        # # Look up are required inputs for the pre-master secret
        # server_certificate = security_params.server_certificate
        # server_public_key = security_params.server_public_key
        #
        # client_public_key = security_params.client_public_key
        # client_private_key = security_params.client_private_key
        security_params = tls_client.tx_security_parameters(active=False)
        key_exchange_type = security_params.cipher_suite.key_exchange_type
        # TODO: Initialize following dictionary at startup
        key_exchange = {
            TLSKeyExchangeTypes.DHE:   TLSClientKeyExchangeDH,
            TLSKeyExchangeTypes.ECDHE: TLSClientKeyExchangeECDH,
            TLSKeyExchangeTypes.RSA:   TLSClientKeyExchangeRSA
        }.get(key_exchange_type)

        return key_exchange(security_params=security_params,
                            client_hello_tls_version=tls_client.client_hello_tls_version,
                            **kwargs)


class TLSClientKeyExchangeDH(TLSClientKeyExchange):
    """
    Client Diffie-Hellman Public Value

        This structure conveys the client's Diffie-Hellman public value
        (Yc) if it was not already included in the client's certificate.

        The encoding used for Yc is determined by the enumerated
        PublicValueEncoding.  This structure is a variant of the client
        key exchange message, and not a message in itself.

    Structure of this message:

      enum { implicit, explicit } PublicValueEncoding;

      implicit
         If the client has sent a certificate which contains a suitable
         Diffie-Hellman key (for fixed_dh client authentication), then
         Yc is implicit and does not need to be sent again.  In this
         case, the client key exchange message will be sent, but it MUST
         be empty.

      explicit
         Yc needs to be sent.

      struct {
          select (PublicValueEncoding) {
              case implicit: struct { };
              case explicit: opaque dh_Yc<1..2^16-1>;
          } dh_public;
      } ClientDiffieHellmanPublic;

      dh_Yc
         The client's Diffie-Hellman public value (Yc).
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.p = None
        self.g = None
        self.public_key = None

        raise NotImplementedError("TODO: Implement")

    @staticmethod
    def parse(frame: bytes, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to RSAPreMasterSecret """
        raise NotImplementedError("TODO: Not yet supported")

    def generate(self) -> Tuple[bytes, bytes]:
        """
        For all key exchange methods, the same algorithm is used to convert
        the pre_master_secret into the master_secret.  The pre_master_secret
        should be deleted from memory once the master_secret has been
        computed.

          master_secret = PRF(pre_master_secret, "master secret",
                              ClientHello.random + ServerHello.random)
                              [0..47];

        The master secret is always exactly 48 bytes in length.  The length
        of the premaster secret will vary depending on key exchange method.

           A conventional Diffie-Hellman computation is performed.  The
           negotiated key (Z) is used as the pre_master_secret, and is converted
           into the master_secret, as specified above.  Leading bytes of Z that
           contain all zero bits are stripped before it is used as the
           pre_master_secret.

           Note: Diffie-Hellman parameters are specified by the server and may
           be either ephemeral or contained within the server's certificate.
        """
        raise NotImplementedError("TODO: Not supported yet")
        # return b''


class TLSClientKeyExchangeECDH(TLSClientKeyExchange):
    """
    Client Elliptical Curve Diffie-Hellman Public Value  (RFC8422)

        This message is used to convey ephemeral data relating to the key
        exchange belonging to the client (such as its ephemeral ECDH public
        key).

    Structure of this message:
        The TLS ClientKeyExchange message is extended as follows.

        enum {
            implicit,
            explicit
        } PublicValueEncoding;

        o implicit, explicit: For ECC cipher suites, this indicates whether
            the client’s ECDH public key is in the client’s certificate
            ("implicit") or is provided, as an ephemeral ECDH public key, in
            the ClientKeyExchange message ("explicit"). The implicit encoding
            is deprecated and is retained here for backward compatibility
            only.

        struct {
            ECPoint ecdh_Yc;
        } ClientECDiffieHellmanPublic;

        ecdh_Yc: Contains the client’s ephemeral ECDH public key as a byte
                 string ECPoint.point, which may represent an elliptic curve point in
                 uncompressed format.

        struct {
            select (KeyExchangeAlgorithm) {
                case ec_diffie_hellman: ClientECDiffieHellmanPublic;
            } exchange_keys;
        } ClientKeyExchange;

    """

    def __init__(self, named_curve_type: Optional[NamedCurveType] = None, **kwargs):
        super().__init__(**kwargs)
        self.named_curve = get_named_curve_by_type(named_curve_type)
        self.server_public_key = self.server_cert.public_key()

    def generate(self) -> Tuple[bytes, bytes]:
        key = ec.generate_private_key(self.named_curve, default_backend())
        shared_key = key.exchange(ec.ECDH(), self.server_public_key)
        serv_key = self.server_public_key.public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)
        return shared_key, serv_key


class TLSClientKeyExchangeRSA(TLSClientKeyExchange):
    def __init__(self, random: Optional[bytes] = None, **kwargs):
        super().__init__(**kwargs)
        self._random = random or os.urandom(46)

    def generate(self) -> Tuple[bytes, bytes]:
        """ Create the pre-master secret and also an encrypted version for transmission"""
        secret = bytes(self._client_hello_tls_version) + self._random
        encrypted = self.server_public_key.encrypt(secret, padding=padding.PKCS1v15())
        return secret, encrypted
