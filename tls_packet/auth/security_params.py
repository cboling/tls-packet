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

import copy
import os
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes
from cryptography.x509 import Certificate
from datetime import datetime
from enum import IntEnum
from typing import Optional, Union

from tls_packet.auth.tls import TLS


class TLSCompressionMethod(IntEnum):
    """ TLS Record compression (RFC 3749) """
    NULL_METHOD = 0
    DEFLATE_METHOD = 1

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


class TLSKeyExchangeTypes(IntEnum):
    ANY = 0
    RSA = 1
    DHE = 2
    ECDHE = 3
    ECDHE_ECDSA = 4  # Added by RFC8422
    ECDHE_RSA = 5  # Added by RFC8422

    PSK = 10
    RSA_PSK = 11
    DHE_PSK = 12
    ECDHE_PSK = 13

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


class TLSAuthentication(IntEnum):
    ANY = 0
    RSA = 1
    DHE = 2
    ECDSA = 4


class SecurityParameters:
    """
    Security Parameters adapted from RFC 5246, Appendix: A.6

       These security parameters are determined by the TLS Handshake
       Protocol and provided as parameters to the TLS record layer in order
       to initialize a connection state.  SecurityParameters includes:

       enum { null(0), (255) } CompressionMethod;
       enum { server, client } ConnectionEnd;
       enum { tls_prf_sha256 } PRFAlgorithm;
       enum { null, rc4, 3des, aes } BulkCipherAlgorithm;
       enum { stream, block, aead } CipherType;
       enum { null, hmac_md5, hmac_sha1, hmac_sha256, hmac_sha384, hmac_sha512} MACAlgorithm;

       /* Other values may be added to the algorithms specified in
       CompressionMethod, PRFAlgorithm, BulkCipherAlgorithm, and
       MACAlgorithm. */

       struct {
           ConnectionEnd          entity;
           PRFAlgorithm           prf_algorithm;
           BulkCipherAlgorithm    bulk_cipher_algorithm;
           CipherType             cipher_type;
           uint8                  enc_key_length;
           uint8                  block_length;
           uint8                  fixed_iv_length;
           uint8                  record_iv_length;
           MACAlgorithm           mac_algorithm;
           uint8                  mac_length;
           uint8                  mac_key_length;
           CompressionMethod      compression_algorithm;
           opaque                 master_secret[48];
           opaque                 client_random[32];
           opaque                 server_random[32];
       } SecurityParameters;

    """

    def __init__(self,
                 prf_algorithm: Optional[bytes] = None,  # PRFAlgorithm
                 compression_algorithm: Optional[TLSCompressionMethod] = TLSCompressionMethod.NULL_METHOD,
                 master_secret: Optional[bytes] = None,
                 client_random: Optional[bytes] = None,
                 server_random: Optional[bytes] = None,
                 client_certificate: Optional[Certificate] = None,
                 client_public_key: Optional[PublicKeyTypes] = None,
                 server_public_key: Optional[PublicKeyTypes] = None,
                 server_certificate: Optional[Certificate] = None,
                 cipher_suite: Optional['CipherSuite'] = None):

        # Desired ones
        client_random = client_random or int(datetime.now().timestamp()).to_bytes(4, 'big') + os.urandom(28)

        self.prf_algorithm = prf_algorithm
        self.compression_algorithm = compression_algorithm

        self._master_secret = master_secret

        self.client_random = client_random
        self.client_certificate = client_certificate
        self._client_public_key = client_public_key
        self._client_private_key = None

        self.server_random = server_random
        self.server_certificate = server_certificate
        self._server_public_key = server_public_key

        self.cipher_suite = cipher_suite

    @property
    def hash_size(self) -> int:
        return 48  # TODO: Implement me

    @property
    def client_public_key(self) -> Union[PublicKeyTypes, None]:
        if self._client_public_key is None and self.client_certificate is not None:
            self._client_public_key = self.client_certificate.public_key()
        return self._client_public_key

    @property
    def client_private_key(self) -> Union[PrivateKeyTypes, None]:
        if self._client_private_key is None and self.client_certificate is not None:
            self._client_private_key = self.client_certificate.private_key()
        return self._client_private_key

    @property
    def server_public_key(self) -> Union[PublicKeyTypes, None]:
        if self._server_public_key is None and self.server_certificate is not None:
            self._server_public_key = self.server_certificate.public_key()
        return self._server_public_key

    @server_public_key.setter
    def server_public_key(self, key: Union[bytes, PublicKeyTypes]) -> None:
        if isinstance(key, bytes):
            key = None  # TODO: Convert to a PublicKeyType
        self._server_public_key = key

    @property
    def master_secret(self) -> bytes:
        return self._master_secret

    @master_secret.setter
    def master_secret(self, secret: bytes) -> None:
        self._master_secret = secret

    def copy(self, **kwargs) -> 'SecurityParameters':
        """ Create a copy of the security parameters and optionally override any existing values """
        dup = copy.copy(self)

        for key, value in kwargs.items():
            if not hasattr(dup, key):
                raise KeyError(f"SecurityParameters does not have the attribute '{key}")

            existing = getattr(dup, key)
            if not isinstance(value, type(existing)) and existing is not None:
                raise ValueError(f"SecurityParameters attribute '{key}' is of type '{type(existing)}. '{value}/{type(value)} provided")

            setattr(dup, key, value)

        return dup
