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
#
#  Inspired by 'tls_client-handshake_pure_python' available on github at:
#               https://github.com/nealyip/tls_client_handshake_pure_python

from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding as AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import Hash, MD5, SHA1, SHA256, SHA384, SHA512, HashAlgorithm
from enum import IntEnum
from typing import Union, Any


class MD5SHA1(SHA1):
    name = "md5-sha1"
    digest_size = 36
    block_size = 64

class TLSMACAlgorithm(IntEnum):
    """ TLS Record compression (RFC 3749) """
    NULL = 0
    HMAC_MD5 = 1
    HMAC_SHA1 = 0x0201
    HMAC_SHA256 = 0x0401
    HMAC_SHA384 = 0x0501
    HMAC_SHA512 = 0x0601
    HMAC_AEAD = 6

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()

"""
# b'\x06\x01'  # rsa_pkcs1_sha512
# b'\x06\x02'  # Signature Algorithm: SHA512 DSA (0x0602)
# b'\x06\x03'  # Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
# b'\x05\x01'  # rsa_pkcs1_sha384
# b'\x05\x02'  # Signature Algorithm: SHA384 DSA (0x0502)
# b'\x05\x03'  # ecdsa_secp384r1_sha384
# b'\x04\x01'  # rsa_pkcs1_sha256
# b'\x04\x02'  # Signature Algorithm: SHA256 DSA (0x0402)
# b'\x04\x03'  # ecdsa_secp256r1_sha256
# b'\x03\x01'  # Signature Algorithm: SHA224 RSA (0x0301)
# b'\x03\x02'  # Signature Algorithm: SHA224 DSA (0x0302)
# b'\x03\x03'  # Signature Algorithm: SHA224 ECDSA (0x0303)
# b'\x02\x01', # rsa_pkcs1_sha1
# b'\x02\x02', # Signature Algorithm: SHA1 DSA (0x0202)
# b'\x02\x03', # Signature Algorithm: ecdsa_sha1 (0x0203)
# b'\x08\x04'  # rsa_pss_rsae_sha256
# b'\x08\x05'  # rsa_pss_rsae_sha384
# b'\x08\x06'  # rsa_pss_rsae_sha512
# b'\x08\x07'  # ed25519
# b'\x08\x08'  # ed448
# b'\x08\x09'  # rsa_pss_pss_sha256
# b'\x08\x0a'  # rsa_pss_pss_sha384
# b'\x08\x0b'  # rsa_pss_pss_sha512
"""


class TLSSignatureAlgorithm:
    """ Base class to simplify signing and verifying data """
    code = TLSMACAlgorithm.NULL

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes],
                 asym_padding: AsymmetricPadding, algorithm: Union[Prehashed, HashAlgorithm]):
        """
        Key is a PublicKeyType for verification, PrivateKeyType for signing
        """
        self._key = key
        self._padding = asym_padding
        self._algorythm = algorithm

    def verify(self, signature: bytes, content: bytes) -> bool:
        try:
            self._key.verify(signature, content, self._padding, self._algorythm)
            return True

        except InvalidSignature as _e:
            return False

    def sign(self, content: bytes) -> bytes:
        return self._key.sign(content, self._padding, self._algorythm)

    @classmethod
    def get_by_code(cls, code: bytes, key: bytes) -> 'TLSSignatureAlgorithm':
        g = globals()
        found = next(filter(lambda x: getattr(g[x], 'code', None) == code, g))
        return g[found](key)


class RsaPkcs1Md5Sha1(TLSSignatureAlgorithm):
    code = b''

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PKCS1v15(), MD5())

    def verify(self, signature, content):
        try:
            self._key.verify(signature, content, padding.PKCS1v15(), MD5SHA1())
            return True

        except InvalidSignature:
            return False


class RsaPkcs1Sha1(TLSSignatureAlgorithm):
    code = TLSMACAlgorithm.HMAC_SHA1

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PKCS1v15(), SHA1())

    def verify(self, signature, content):
        try:
            self._key.verify(signature, content, padding.PKCS1v15(), SHA1())
            return True

        except InvalidSignature:
            return False


class RsaPkcs1Sha256(TLSSignatureAlgorithm):
    code = TLSMACAlgorithm.HMAC_SHA256

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PKCS1v15(), SHA256())

    def verify(self, signature, content):
        try:
            self._key.verify(signature, content, padding.PKCS1v15(), SHA256())
            return True

        except InvalidSignature:
            return False


class RsaPssRsaeSha256(TLSSignatureAlgorithm):
    code = b'\x08\x09'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PSS(mgf=padding.MGF1(SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                         SHA256())

    def verify(self, signature, content):
        try:
            self._key.verify(signature, content, padding.PSS(
                mgf=padding.MGF1(SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), SHA256())
            return True

        except InvalidSignature:
            return False


class RsaPssRsaeSha384(TLSSignatureAlgorithm):
    code = b'\x08\x05'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PSS(mgf=padding.MGF1(SHA384()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                         SHA384())

    def verify(self, signature, content):
        try:
            self._key.verify(signature, content, padding.PSS(
                mgf=padding.MGF1(SHA384()),
                salt_length=padding.PSS.MAX_LENGTH
            ), SHA384())
            return True

        except InvalidSignature:
            return False


class EcdsaSecp256r1Sha256(TLSSignatureAlgorithm):
    code = b'\x04\x03'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, None, ec.ECDSA(SHA256()))

    def verify(self, signature, content):
        try:
            self._key.verify(signature, content, ec.ECDSA(SHA256()))
            return True

        except InvalidSignature:
            return False


class EcdsaSecp384r1Sha384(TLSSignatureAlgorithm):
    code = b'\x05\x03'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, None,  ec.ECDSA(SHA384()))

    def verify(self, signature: bytes, content: bytes) -> bool:
        try:
            self._key.verify(signature, content, ec.ECDSA(SHA384()))
            return True

        except InvalidSignature:
            return False
