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
# Updated 2023/06/24 on updated Ubuntu 20.04.01.
# To update this list, run:  .../packet/util/mk_cipher
#  cboling@tvm01:/opt/repos/cboling/packet/util$ g++ -o mk_cipher mk_cipher_list.c -lssl -lcrypto
#  cboling@tvm01:/opt/repos/cboling/packet/util$ ./mk_cipher

from copy import deepcopy
from typing import Dict, Union, Type, Collection, Optional

from tls_packet.auth.tls import TLS, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3

CipherSuiteDict = Type[Dict[str, Dict[str, Union[int, str]]]]

CIPHER_SUITES = {
    'TLS_AES_256_GCM_SHA384':        {
        'id':             4866,
        'version':        'TLSv1.3',
        'tls_name':       'TLS_AES_256_GCM_SHA384',
        'key_exchange':   'ANY',
        'authentication': 'ANY',
        'bits':           256,
        'mac':            'SHA1',
    },
    'TLS_CHACHA20_POLY1305_SHA256':  {
        'id':             4867,
        'version':        'TLSv1.3',
        'tls_name':       'TLS_CHACHA20_POLY1305_SHA256',
        'key_exchange':   'ANY',
        'authentication': 'ANY',
        'bits':           256,
        'mac':            'SHA1',
    },
    'TLS_AES_128_GCM_SHA256':        {
        'id':             4865,
        'version':        'TLSv1.3',
        'tls_name':       'TLS_AES_128_GCM_SHA256',
        'key_exchange':   'ANY',
        'authentication': 'ANY',
        'bits':           128,
        'mac':            'SHA1',
    },
    'ECDHE-ECDSA-AES256-GCM-SHA384': {
        'id':             49196,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'key_exchange':   'ECDHE',
        'authentication': 'ECDSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'ECDHE-RSA-AES256-GCM-SHA384':   {
        'id':             49200,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'key_exchange':   'ECDHE',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'DHE-RSA-AES256-GCM-SHA384':     {
        'id':             159,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        'key_exchange':   'DHE',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'ECDHE-ECDSA-CHACHA20-POLY1305': {
        'id':             52393,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        'key_exchange':   'ECDHE',
        'authentication': 'ECDSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'ECDHE-RSA-CHACHA20-POLY1305':   {
        'id':             52392,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        'key_exchange':   'ECDHE',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'DHE-RSA-CHACHA20-POLY1305':     {
        'id':             52394,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        'key_exchange':   'DHE',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'ECDHE-ECDSA-AES128-GCM-SHA256': {
        'id':             49195,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'key_exchange':   'ECDHE',
        'authentication': 'ECDSA',
        'bits':           128,
        'mac':            'SHA1',
    },
    'ECDHE-RSA-AES128-GCM-SHA256':   {
        'id':             49199,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'key_exchange':   'ECDHE',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            'SHA1',
    },
    'DHE-RSA-AES128-GCM-SHA256':     {
        'id':             158,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        'key_exchange':   'DHE',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            'SHA1',
    },
    'ECDHE-ECDSA-AES256-SHA384':     {
        'id':             49188,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        'key_exchange':   'ECDHE',
        'authentication': 'ECDSA',
        'bits':           256,
        'mac':            'DES-EDE',
    },
    'ECDHE-RSA-AES256-SHA384':       {
        'id':             49192,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'key_exchange':   'ECDHE',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'DES-EDE',
    },
    'DHE-RSA-AES256-SHA256':         {
        'id':             107,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
        'key_exchange':   'DHE',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            '',
    },
    'ECDHE-ECDSA-AES128-SHA256':     {
        'id':             49187,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'key_exchange':   'ECDHE',
        'authentication': 'ECDSA',
        'bits':           128,
        'mac':            '',
    },
    'ECDHE-RSA-AES128-SHA256':       {
        'id':             49191,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'key_exchange':   'ECDHE',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            '',
    },
    'DHE-RSA-AES128-SHA256':         {
        'id':             103,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
        'key_exchange':   'DHE',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            '',
    },
    'ECDHE-ECDSA-AES256-SHA':        {
        'id':             49162,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'key_exchange':   'ECDHE',
        'authentication': 'ECDSA',
        'bits':           256,
        'mac':            '',
    },
    'ECDHE-RSA-AES256-SHA':          {
        'id':             49172,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        'key_exchange':   'ECDHE',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            '',
    },
    'ECDHE-ECDSA-AES128-SHA':        {
        'id':             49161,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        'key_exchange':   'ECDHE',
        'authentication': 'ECDSA',
        'bits':           128,
        'mac':            '',
    },
    'ECDHE-RSA-AES128-SHA':          {
        'id':             49171,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'key_exchange':   'ECDHE',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            '',
    },
    'RSA-PSK-AES256-GCM-SHA384':     {
        'id':             173,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
        'key_exchange':   'RSA_PSK',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'DHE-PSK-AES256-GCM-SHA384':     {
        'id':             171,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
        'key_exchange':   'DHE-PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            'SHA1',
    },
    'RSA-PSK-CHACHA20-POLY1305':     {
        'id':             52398,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256',
        'key_exchange':   'RSA_PSK',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'DHE-PSK-CHACHA20-POLY1305':     {
        'id':             52397,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
        'key_exchange':   'DHE-PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            'SHA1',
    },
    'ECDHE-PSK-CHACHA20-POLY1305':   {
        'id':             52396,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
        'key_exchange':   'ECDHE-PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            'SHA1',
    },
    'AES256-GCM-SHA384':             {
        'id':             157,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'key_exchange':   'RSA',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'SHA1',
    },
    'PSK-AES256-GCM-SHA384':         {
        'id':             169,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_PSK_WITH_AES_256_GCM_SHA384',
        'key_exchange':   'PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            'SHA1',
    },
    'PSK-CHACHA20-POLY1305':         {
        'id':             52395,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256',
        'key_exchange':   'PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            'SHA1',
    },
    'RSA-PSK-AES128-GCM-SHA256':     {
        'id':             172,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
        'key_exchange':   'RSA_PSK',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            'SHA1',
    },
    'DHE-PSK-AES128-GCM-SHA256':     {
        'id':             170,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
        'key_exchange':   'DHE-PSK',
        'authentication': 'PSK',
        'bits':           128,
        'mac':            'SHA1',
    },
    'AES128-GCM-SHA256':             {
        'id':             156,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_RSA_WITH_AES_128_GCM_SHA256',
        'key_exchange':   'RSA',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            'SHA1',
    },
    'PSK-AES128-GCM-SHA256':         {
        'id':             168,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_PSK_WITH_AES_128_GCM_SHA256',
        'key_exchange':   'PSK',
        'authentication': 'PSK',
        'bits':           128,
        'mac':            'SHA1',
    },
    'AES256-SHA256':                 {
        'id':             61,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_RSA_WITH_AES_256_CBC_SHA256',
        'key_exchange':   'RSA',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            '',
    },
    'AES128-SHA256':                 {
        'id':             60,
        'version':        'TLSv1.2',
        'tls_name':       'TLS_RSA_WITH_AES_128_CBC_SHA256',
        'key_exchange':   'RSA',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            '',
    },
    'ECDHE-PSK-AES256-CBC-SHA384':   {
        'id':             49208,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
        'key_exchange':   'ECDHE-PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            'DES-EDE',
    },
    'ECDHE-PSK-AES256-CBC-SHA':      {
        'id':             49206,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
        'key_exchange':   'ECDHE-PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            '',
    },
    'RSA-PSK-AES256-CBC-SHA384':     {
        'id':             183,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
        'key_exchange':   'RSA_PSK',
        'authentication': 'RSA',
        'bits':           256,
        'mac':            'DES-EDE',
    },
    'DHE-PSK-AES256-CBC-SHA384':     {
        'id':             179,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
        'key_exchange':   'DHE-PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            'DES-EDE',
    },
    'PSK-AES256-CBC-SHA384':         {
        'id':             175,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_PSK_WITH_AES_256_CBC_SHA384',
        'key_exchange':   'PSK',
        'authentication': 'PSK',
        'bits':           256,
        'mac':            'DES-EDE',
    },
    'ECDHE-PSK-AES128-CBC-SHA256':   {
        'id':             49207,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
        'key_exchange':   'ECDHE-PSK',
        'authentication': 'PSK',
        'bits':           128,
        'mac':            '',
    },
    'ECDHE-PSK-AES128-CBC-SHA':      {
        'id':             49205,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
        'key_exchange':   'ECDHE-PSK',
        'authentication': 'PSK',
        'bits':           128,
        'mac':            '',
    },
    'RSA-PSK-AES128-CBC-SHA256':     {
        'id':             182,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
        'key_exchange':   'RSA_PSK',
        'authentication': 'RSA',
        'bits':           128,
        'mac':            '',
    },
    'DHE-PSK-AES128-CBC-SHA256':     {
        'id':             178,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
        'key_exchange':   'DHE-PSK',
        'authentication': 'PSK',
        'bits':           128,
        'mac':            '',
    },
    'PSK-AES128-CBC-SHA256':         {
        'id':             174,
        'version':        'TLSv1.0',
        'tls_name':       'TLS_PSK_WITH_AES_128_CBC_SHA256',
        'key_exchange':   'PSK',
        'authentication': 'PSK',
        'bits':           128,
        'mac':            '',
    },
}


def version_to_tls(version: str) -> Union[TLS, None]:
    return {
        "TLSv1.0": TLSv1(),
        "TLSv1.1": TLSv1_1(),
        "TLSv1.2": TLSv1_2(),
        "TLSv1.3": TLSv1_3()
    }.get(version, None)


def get_cipher_suites_by_version(version: TLS, excluded: Optional[Collection[str]] = None) -> CipherSuiteDict:
    """ Return suites supported by a TLS version """
    excluded = excluded or []
    # TODO: Comparison below is not really valid.  In TLSv1.3, some older suites were deprecated
    if isinstance(version, TLSv1_3):
        raise NotImplementedError("v1.3 is not yet supported, see comment above")

    results = {k: v for k, v in CIPHER_SUITES.items()
               if version_to_tls(v["version"]) and version_to_tls(v["version"]) <= version
               and all(dont_want not in v["key_exchange"].upper() for dont_want in excluded)}

    return deepcopy(results)


class CipherSuite:
    def __init__(self, tls_version, client_random, server_random, server_cert, cipher_suite):
        self.properties = cipher_suite
        self.tls_version = tls_version
        self.client_random = client_random
        self.server_random = server_random
        self.server_cert = server_cert
    #     ke = cipher_suite['key_exchange'].split('/')
    #     args = [tls_version, client_random, server_random, server_cert, ke[1] if len(ke) > 1 else None]
    #     self.key_exchange: sim.cpe.tls.key_exchange.KeyExchange = getattr(sim.cpe.tls.key_exchange, ke[0])(*args)
    #     self.keys = dict()
    #
    # def __str__(self):
    #     return self.properties['openssl_name']
    #
    # @property
    # def security_parameters(self):
    #     enc_algo = self.properties.get('encryption_algorithm')
    #     sp = {
    #         'key_material_length': int(enc_algo[enc_algo.find('(') + 1:enc_algo.find(')')], 10) // 8,
    #     }
    #     if self.properties.get('message_authentication_code') == 'AEAD':
    #         sp['hash_size'] = 0
    #         sp['IV_size'] = 4
    #     else:
    #         sp['hash_size'] = self.signature_algorithm.digest_size
    #         sp['IV_size'] = 16
    #     return sp
    #
    # @classmethod
    # def get_from_id(cls, tls_version, client_random, server_random, server_cert, id):
    #     id = '0x{:04X}'.format(int.from_bytes(id, 'big'))
    #     found = next(filter(lambda cipher: CIPHER_SUITES[cipher]['id'] == id, CIPHER_SUITES))
    #
    #     return CipherSuite(tls_version, client_random, server_random, server_cert, CIPHER_SUITES[found])
    #
    # @property
    # def pre_master_secret(self):
    #     raise ValueError('pre_master_secret is not obtainable.')
    #
    # @pre_master_secret.setter
    # def pre_master_secret(self, value):
    #     self._derive_key(value)
    #
    # @property
    # def signature_algorithm(self):
    #     name = self.properties.get('message_authentication_code')
    #     if name == 'AEAD':
    #         openssl_name = self.properties.get('openssl_name')
    #         name = openssl_name[openssl_name.rfind('-')+1:]
    #         name = 'SHA1' if name == 'SHA' else name
    #     return getattr(sim.cpe.tls.signature_algorithms, name)()
    #
    # @property
    # def encryption_algorithm(self) -> sim.cpe.tls.encryption_algorithms.EncryptionAlgorithm:
    #     text = self.properties.get('encryption_algorithm')
    #     assert text.find('AES') > -1, NotImplementedError('Not support {}'.format(text))
    #     text = text.split('(')
    #     return getattr(sim.cpe.tls.encryption_algorithms, text[0])()
    #
    # def parse_key_exchange_params(self, params_bytes):
    #     self.key_exchange.parse_params(params_bytes)
    #
    # def prf(self, secret, label, seed, output_length):
    #     return prf(self.tls_version, self.signature_algorithm, secret, label, seed, output_length)
    #
    # def _derive_key(self, value):
    #     master_secret = self.prf(value, b'master secret', self.client_random + self.server_random, 48)
    #
    #     # key_block
    #     kb = self.prf(master_secret, b'key expansion', self.server_random + self.client_random, 200)
    #
    #     keys, sp = {}, self.security_parameters
    #
    #     keys['master_secret'] = master_secret
    #     keys['client_write_mac_key'], kb = kb[:sp['hash_size']], kb[sp['hash_size']:]
    #     keys['server_write_mac_key'], kb = kb[:sp['hash_size']], kb[sp['hash_size']:]
    #     keys['client_write_key'], kb = kb[:sp['key_material_length']], kb[sp['key_material_length']:]
    #     keys['server_write_key'], kb = kb[:sp['key_material_length']], kb[sp['key_material_length']:]
    #     keys['client_write_iv'], kb = kb[:sp['IV_size']], kb[sp['IV_size']:]
    #     keys['server_write_iv'], kb = kb[:sp['IV_size']], kb[sp['IV_size']:]
    #
    #     self.keys = keys
    #
    # def encrypt(self, content_bytes, *, seq_num, content_type, encrypt_from='client'):
    #     iv = self.keys['{}_write_iv'.format(encrypt_from)]
    #     args = [self.tls_version, self.keys['{}_write_key'.format(encrypt_from)], iv, content_bytes]
    #
    #     seq_bytes = int_to_bytes(seq_num, 8)
    #     additional_bytes = seq_bytes + content_type + self.tls_version
    #
    #     kwargs = {
    #         'add': additional_bytes,
    #         'hash_algorithm': self.signature_algorithm,
    #         'sign_key': self.keys['{}_write_mac_key'.format(encrypt_from)]
    #     }
    #     return self.encryption_algorithm.encrypt(*args, **kwargs)
    #
    # def decrypt(self, encrypted_bytes, *, seq_num, content_type, decrypt_from='server'):
    #     key = self.keys['{}_write_key'.format(decrypt_from)]
    #     seq_bytes = int_to_bytes(seq_num, 8)
    #     additional_bytes = seq_bytes + content_type + self.tls_version
    #
    #     kwargs = {
    #         'iv': self.keys['{}_write_iv'.format(decrypt_from)],
    #         'tls_version': self.tls_version,
    #         'key': key,
    #         'encrypted': encrypted_bytes,
    #         'add': additional_bytes,
    #         'hash_algorithm': self.signature_algorithm,
    #         'sign_key': self.keys['{}_write_mac_key'.format(decrypt_from)]
    #     }
    #
    #     return self.encryption_algorithm.decrypt(**kwargs)
    #
    # def sign_verify_data(self, message):
    #     data = self.hash_verify_data(message)
    #     return self.prf(self.keys.get('master_secret'), sim.cpe.tls.constants.LABEL_CLIENT_FINISHED, data, 12)
    #
    # def verify_verify_data(self, message, signature):
    #     data = self.hash_verify_data(message)
    #     generated = self.prf(self.keys.get('master_secret'), sim.cpe.tls.constants.LABEL_SERVER_FINISHED, data, 12)
    #     assert signature == generated, ValueError('Signature incorrect')
    #
    # def hash_verify_data(self, message):
    #     if self.tls_version < sim.cpe.tls.tls.TLSV1_2:
    #         algorithm = sim.cpe.tls.signature_algorithms.MD5SHA1()
    #     else:
    #         algorithm = self.signature_algorithm
    #         if algorithm.digest_size < 32:
    #             algorithm = sim.cpe.tls.signature_algorithms.SHA256()
    #     _hash = sim.cpe.tls.signature_algorithms.Hash(algorithm, sim.cpe.tls.signature_algorithms.default_backend())
    #     _hash.update(message)
    #     return _hash.finalize()
