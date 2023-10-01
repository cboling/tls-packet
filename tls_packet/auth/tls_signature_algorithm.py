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

from typing import Union, Any

from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import Hash, MD5, SHA1, SHA256, SHA384, SHA512, HashAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec


class SignatureAlgorithm:
    """ Base class to simplify signing and verifying data """
    code = b''

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes],
                 padding: AsymmetricPadding, algorithm: asym_utils.Prehashed | hashes.HashAlgorithm):
        """
        Key is a PublicKeyType for verification, PrivateKeyType for signing
        """
        self._key = key
        self._padding = padding
        self._algorythm = algorithm

    def verify(self, signature: bytes, content: bytes) -> bool:
        try:
            self._key.verify(signature, content, self._padding, self._algorythm)
            return True

        except InvalidSignature:
            return False

    def sign(self, content: bytes) -> bytes:
        return self._key.sign(content, self._padding, self._algorythm)

    @classmethod
    def get_by_code(cls, code: bytes, key: bytes) -> SignatureAlgorithm:
        g = globals()
        found = next(filter(lambda x: getattr(g[x], 'code', None) == code, g))
        return g[found](key)


class RsaPkcs1Md5Sha1(SignatureAlgorithm):
    code = b''

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PKCS1v15(), MD5SHA1())


class RsaPkcs1Sha1(SignatureAlgorithm):
    code = b'\x02\x01'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PKCS1v15(), SHA1())


class RsaPkcs1Sha256(SignatureAlgorithm):
    code = b'\x04\x01'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PKCS1v15(), SHA256())


class RsaPssRsaeSha256(SignatureAlgorithm):
    code = b'\x08\x09'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PSS(mgf=padding.MGF1(SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                         SHA256())


class RsaPssRsaeSha384(SignatureAlgorithm):
    code = b'\x08\x05'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, padding.PSS(mgf=padding.MGF1(SHA384()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                         SHA384())


class EcdsaSecp256r1Sha256(SignatureAlgorithm):
    code = b'\x04\x03'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, None, ec.ECDSA(SHA256()))

    def verify(self, signature: bytes, content: bytes) -> bool:
        try:
            self._key.verify(signature, content, ec.ECDSA(SHA256()))
            return True

        except InvalidSignature:
            return False


class EcdsaSecp384r1Sha384(SignatureAlgorithm):
    code = b'\x05\x03'

    def __init__(self, key: Union[PublicKeyTypes, PrivateKeyTypes]):
        super().__init__(key, None,  ec.ECDSA(SHA384()))

    def verify(self, signature: bytes, content: bytes) -> bool:
        try:
            self._key.verify(signature, content, ec.ECDSA(SHA384()))
            return True

        except InvalidSignature:
            return False


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