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
from enum import IntEnum
from typing import Optional


class TLSCompressionMethod(IntEnum):
    """ TLS Record compression (RFC 3749) """
    NULL_METHOD = 0
    DEFLATE_METHOD = 1

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


class TLSMACAlgorithm(IntEnum):
    """ TLS Record compression (RFC 3749) """
    NULL = 0
    HMAC_MD5 = 1
    HMAC_SHA1 = 2
    HMAC_SHA256 = 3
    HMAC_SHA384 = 4
    HMAC_SHA512 = 4

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


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
                 bulk_cipher_algorithm: Optional[bytes] = None,  # BulkCipherAlgorithm
                 cipher_type: Optional[bytes] = None,  # CipherType
                 enc_key_length: Optional[int] = 0,
                 block_length: Optional[int] = 0,
                 fixed_iv_length: Optional[int] = 0,
                 record_iv_length: Optional[int] = 0,
                 mac_algorithm: Optional[TLSMACAlgorithm] = TLSMACAlgorithm.NULL,
                 mac_length: Optional[int] = 0,
                 mac_key_length: Optional[int] = 0,
                 compression_algorithm: Optional[TLSCompressionMethod] = TLSCompressionMethod.NULL_METHOD,
                 master_secret: Optional[bytes] = None,
                 client_random: Optional[bytes] = None,
                 server_random: Optional[bytes] = None):

        client_random = client_random or os.urandom(32)

        self.prf_algorithm = prf_algorithm
        self.bulk_cipher_algorithm = bulk_cipher_algorithm
        self.cipher_type = cipher_type
        self.enc_key_length = enc_key_length
        self.block_length = block_length
        self.fixed_iv_length = fixed_iv_length
        self.record_iv_length = record_iv_length
        self.mac_algorithm = mac_algorithm
        self.mac_length = mac_length
        self.mac_key_length = mac_key_length
        self.compression_algorithm = compression_algorithm
        self.master_secret = master_secret
        self.client_random = client_random
        self.server_random = server_random

    def copy(self, **kwargs) -> 'SecurityParameters':
        """ Create a copy of the security parameters and optionally override any existing values """
        dup = copy.copy(self)

        for key, value in kwargs.items():
            if not hasattr(dup, key):
                raise KeyError(f"SecurityParameters does not have the attribute '{key}")

            existing = getattr(dup, key)
            if not isinstance(value, type(existing)):
                raise ValueError(f"SecurityParameters attribute '{key}' is of type '{type(existing)}. '{value}/{type(value)} provided")

            setattr(dup, key, value)

        return dup
