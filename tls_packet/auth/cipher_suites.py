# Mostly from https://github.com/nealyip/tls_client_handshake_pure_python

import math
from copy import deepcopy
from typing import Optional, Iterable, Union, Type, Dict, Any
# import constants
# import encryption_algorithms
# import key_exchange
# import signature_algorithms
# from prf import prf as _prf


from tls_packet.auth.tls import TLS, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3
from tls_packet.auth.security_params import TLSMACAlgorithm, TLSKeyExchangeTypes, TLSAuthentication
from tls_packet.auth.encryption_algorithms import AES, AESGCM



CipherSuiteDict = Type[Dict[int, Dict[str, Any]]]

"""
Obtainable from openssl ciphers -V
"""
MINIMAL_SUITES = True

if MINIMAL_SUITES:
    # TODO, Comment out the last one to test a Failure mesage due to no shared cipher
    CIPHER_SUITES = {
        0x003C: {
            'tls_name':                    'TLS_RSA_WITH_AES_128_CBC_SHA256',
            'openssl_name':                'AES128-SHA256',
            'version':                     TLSv1_2,
            'key_exchange':                TLSKeyExchangeTypes.RSA,
            'authentication':              TLSAuthentication.RSA,
            'encryption_algorithm':        AES,
            'key_material_bits':           128,
            'message_authentication_code': TLSMACAlgorithm.HMAC_SHA256
        },
        0x009F: {
            'tls_name':                    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
            'openssl_name':                'DHE-RSA-AES256-GCM-SHA384',
            'version':                     TLSv1_2,
            'key_exchange':                TLSKeyExchangeTypes.DHE,
            'authentication':              TLSAuthentication.RSA,
            'encryption_algorithm':        AESGCM,
            'key_material_bits':           256,
            'message_authentication_code': TLSMACAlgorithm.HMAC_SHA384
        },
        0xC014: {    # TODO: Comment this one out to force an Alert on ClientHello due to no shared ciphers
            'tls_name':                    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            'openssl_name':                'ECDHE-RSA-AES256-SHA',
            'version':                     TLSv1,                       # Listed by openssl as SSLv3
            'key_exchange':                TLSKeyExchangeTypes.ECDHE,
            'authentication':              TLSAuthentication.RSA,
            'encryption_algorithm':        AES,
            'key_material_bits':           256,
            'message_authentication_code': TLSMACAlgorithm.HMAC_SHA1
        },
    }
else:
    CIPHER_SUITES = {
    'RC4-MD5': {
        'id': '0x0004',
        'tls_name': 'SSL_CK_RC4_128_WITH_MD5',
        'openssl_name': 'RC4-MD5',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'RC4(128)',
        'message_authentication_code': 'MD5',
    },
    'RC4-SHA': {
        'id': '0x0005',
        'tls_name': 'TLS_RSA_WITH_RC4_128_SHA',
        'openssl_name': 'RC4-SHA',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'RC4(128)',
        'message_authentication_code': 'SHA1'
    },
    'IDEA-CBC-SHA': {
        'id': '0x0007',
        'tls_name': 'TLS_RSA_WITH_IDEA_CBC_SHA',
        'openssl_name': 'IDEA-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'IDEA(128)',
        'message_authentication_code': 'SHA1'
    },
    'DES-CBC3-SHA': {
        'id': '0x000A',
        'tls_name': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'DH-DSS-DES-CBC3-SHA': {
        'id': '0x000D',
        'tls_name': 'SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'DH-DSS-DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'DH-RSA-DES-CBC3-SHA': {
        'id': '0x0010',
        'tls_name': 'SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'DH-RSA-DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'EDH-DSS-DES-CBC3-SHA': {
        'id': '0x0013',
        'tls_name': 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'EDH-DSS-DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'EDH-RSA-DES-CBC3-SHA': {
        'id': '0x0016',
        'tls_name': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'EDH-RSA-DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'AES128-SHA': {
        'id': '0x002F',
        'tls_name': 'TLS_RSA_WITH_AES_128_CBC_SHA',
        'openssl_name': 'AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'DH-DSS-AES128-SHA': {
        'id': '0x0030',
        'tls_name': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
        'openssl_name': 'DH-DSS-AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'DH-RSA-AES128-SHA': {
        'id': '0x0031',
        'tls_name': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
        'openssl_name': 'DH-RSA-AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-DSS-AES128-SHA': {
        'id': '0x0032',
        'tls_name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
        'openssl_name': 'DHE-DSS-AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-RSA-AES128-SHA': {
        'id': '0x0033',
        'tls_name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        'openssl_name': 'DHE-RSA-AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'AES256-SHA': {
        'id': '0x0035',
        'tls_name': 'TLS_RSA_WITH_AES_256_CBC_SHA',
        'openssl_name': 'AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'DH-DSS-AES256-SHA': {
        'id': '0x0036',
        'tls_name': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
        'openssl_name': 'DH-DSS-AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'DH-RSA-AES256-SHA': {
        'id': '0x0037',
        'tls_name': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
        'openssl_name': 'DH-RSA-AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-DSS-AES256-SHA': {
        'id': '0x0038',
        'tls_name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
        'openssl_name': 'DHE-DSS-AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-RSA-AES256-SHA': {
        'id': '0x0039',
        'tls_name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
        'openssl_name': 'DHE-RSA-AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'AES128-SHA256': {
        'id': '0x003C',
        'tls_name': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'AES256-SHA256': {
        'id': '0x003D',
        'tls_name': 'TLS_RSA_WITH_AES_256_CBC_SHA256',
        'openssl_name': 'AES256-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA256'
    },
    'DH-DSS-AES128-SHA256': {
        'id': '0x003E',
        'tls_name': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'DH-DSS-AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'DH-RSA-AES128-SHA256': {
        'id': '0x003F',
        'tls_name': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'DH-RSA-AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'DHE-DSS-AES128-SHA256': {
        'id': '0x0040',
        'tls_name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'DHE-DSS-AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'CAMELLIA128-SHA': {
        'id': '0x0041',
        'tls_name': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
        'openssl_name': 'CAMELLIA128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'Camellia(128)',
        'message_authentication_code': 'SHA1'
    },
    'DH-DSS-CAMELLIA128-SHA': {
        'id': '0x0042',
        'tls_name': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
        'openssl_name': 'DH-DSS-CAMELLIA128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'Camellia(128)',
        'message_authentication_code': 'SHA1'
    },
    'DH-RSA-CAMELLIA128-SHA': {
        'id': '0x0043',
        'tls_name': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
        'openssl_name': 'DH-RSA-CAMELLIA128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'Camellia(128)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-DSS-CAMELLIA128-SHA': {
        'id': '0x0044',
        'tls_name': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
        'openssl_name': 'DHE-DSS-CAMELLIA128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'Camellia(128)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-RSA-CAMELLIA128-SHA': {
        'id': '0x0045',
        'tls_name': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
        'openssl_name': 'DHE-RSA-CAMELLIA128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'Camellia(128)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-RSA-AES128-SHA256': {
        'id': '0x0067',
        'tls_name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'DHE-RSA-AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'DH-DSS-AES256-SHA256': {
        'id': '0x0068',
        'tls_name': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
        'openssl_name': 'DH-DSS-AES256-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA256'
    },
    'DH-RSA-AES256-SHA256': {
        'id': '0x0069',
        'tls_name': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
        'openssl_name': 'DH-RSA-AES256-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA256'
    },
    'DHE-DSS-AES256-SHA256': {
        'id': '0x006A',
        'tls_name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
        'openssl_name': 'DHE-DSS-AES256-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA256'
    },
    'DHE-RSA-AES256-SHA256': {
        'id': '0x006B',
        'tls_name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
        'openssl_name': 'DHE-RSA-AES256-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA256'
    },
    'CAMELLIA256-SHA': {
        'id': '0x0084',
        'tls_name': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
        'openssl_name': 'CAMELLIA256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'Camellia(256)',
        'message_authentication_code': 'SHA1'
    },
    'DH-DSS-CAMELLIA256-SHA': {
        'id': '0x0085',
        'tls_name': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
        'openssl_name': 'DH-DSS-CAMELLIA256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'Camellia(256)',
        'message_authentication_code': 'SHA1'
    },
    'DH-RSA-CAMELLIA256-SHA': {
        'id': '0x0086',
        'tls_name': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
        'openssl_name': 'DH-RSA-CAMELLIA256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'Camellia(256)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-DSS-CAMELLIA256-SHA': {
        'id': '0x0087',
        'tls_name': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
        'openssl_name': 'DHE-DSS-CAMELLIA256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'Camellia(256)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-RSA-CAMELLIA256-SHA': {
        'id': '0x0088',
        'tls_name': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
        'openssl_name': 'DHE-RSA-CAMELLIA256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'Camellia(256)',
        'message_authentication_code': 'SHA1'
    },
    'PSK-RC4-SHA': {
        'id': '0x008A',
        'tls_name': 'TLS_PSK_WITH_RC4_128_SHA',
        'openssl_name': 'PSK-RC4-SHA',
        'version': 'SSLv3',
        'key_exchange': 'PSK',
        'authentication': 'PSK',
        'encryption_algorithm': 'RC4(128)',
        'message_authentication_code': 'SHA1'
    },
    'PSK-3DES-EDE-CBC-SHA': {
        'id': '0x008B',
        'tls_name': 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'PSK-3DES-EDE-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'PSK',
        'authentication': 'PSK',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'PSK-AES128-CBC-SHA': {
        'id': '0x008C',
        'tls_name': 'TLS_PSK_WITH_AES_128_CBC_SHA',
        'openssl_name': 'PSK-AES128-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'PSK',
        'authentication': 'PSK',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'PSK-AES256-CBC-SHA': {
        'id': '0x008D',
        'tls_name': 'TLS_PSK_WITH_AES_256_CBC_SHA',
        'openssl_name': 'PSK-AES256-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'PSK',
        'authentication': 'PSK',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'SEED-SHA': {
        'id': '0x0096',
        'tls_name': 'TLS_RSA_WITH_SEED_CBC_SHA',
        'openssl_name': 'SEED-SHA',
        'version': 'SSLv3',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'SEED(128)',
        'message_authentication_code': 'SHA1'
    },
    'DH-DSS-SEED-SHA': {
        'id': '0x0097',
        'tls_name': 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
        'openssl_name': 'DH-DSS-SEED-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'SEED(128)',
        'message_authentication_code': 'SHA1'
    },
    'DH-RSA-SEED-SHA': {
        'id': '0x0098',
        'tls_name': 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
        'openssl_name': 'DH-RSA-SEED-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'SEED(128)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-DSS-SEED-SHA': {
        'id': '0x0099',
        'tls_name': 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
        'openssl_name': 'DHE-DSS-SEED-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'SEED(128)',
        'message_authentication_code': 'SHA1'
    },
    'DHE-RSA-SEED-SHA': {
        'id': '0x009A',
        'tls_name': 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
        'openssl_name': 'DHE-RSA-SEED-SHA',
        'version': 'SSLv3',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'SEED(128)',
        'message_authentication_code': 'SHA1'
    },
    'AES128-GCM-SHA256': {
        'id': '0x009C',
        'tls_name': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'AES256-GCM-SHA384': {
        'id': '0x009D',
        'tls_name': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'RSA',
        'authentication': 'RSA',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'DHE-RSA-AES128-GCM-SHA256': {
        'id': '0x009E',
        'tls_name': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'DHE-RSA-AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'DHE-RSA-AES256-GCM-SHA384': {
        'id': '0x009F',
        'tls_name': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'DHE-RSA-AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'DH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'DH-RSA-AES128-GCM-SHA256': {
        'id': '0x00A0',
        'tls_name': 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'DH-RSA-AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'DH-RSA-AES256-GCM-SHA384': {
        'id': '0x00A1',
        'tls_name': 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'DH-RSA-AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'DH/RSA',
        'authentication': 'DH',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'DHE-DSS-AES128-GCM-SHA256': {
        'id': '0x00A2',
        'tls_name': 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'DHE-DSS-AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'DHE-DSS-AES256-GCM-SHA384': {
        'id': '0x00A3',
        'tls_name': 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'DHE-DSS-AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'DH',
        'authentication': 'DSS',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'DH-DSS-AES128-GCM-SHA256': {
        'id': '0x00A4',
        'tls_name': 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'DH-DSS-AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'DH-DSS-AES256-GCM-SHA384': {
        'id': '0x00A5',
        'tls_name': 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'DH-DSS-AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'DH/DSS',
        'authentication': 'DH',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'ECDH-ECDSA-RC4-SHA': {
        'id': '0xC002',
        'tls_name': 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
        'openssl_name': 'ECDH-ECDSA-RC4-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH/ECDSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'RC4(128)',
        'message_authentication_code': 'SHA1'
    },
    'ECDH-ECDSA-DES-CBC3-SHA': {
        'id': '0xC003',
        'tls_name': 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'ECDH-ECDSA-DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH/ECDSA',
        'authentication': 'ECDH',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'ECDH-ECDSA-AES128-SHA': {
        'id': '0xC004',
        'tls_name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
        'openssl_name': 'ECDH-ECDSA-AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH/ECDSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'ECDH-ECDSA-AES256-SHA': {
        'id': '0xC005',
        'tls_name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
        'openssl_name': 'ECDH-ECDSA-AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH/ECDSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-ECDSA-RC4-SHA': {
        'id': '0xC007',
        'tls_name': 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
        'openssl_name': 'ECDHE-ECDSA-RC4-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH',
        'authentication': 'ECDSA',
        'encryption_algorithm': 'RC4(128)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-ECDSA-DES-CBC3-SHA': {
        'id': '0xC008',
        'tls_name': 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'ECDHE-ECDSA-DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH',
        'authentication': 'ECDSA',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-ECDSA-AES128-SHA': {
        'id': '0xC009',
        'tls_name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        'openssl_name': 'ECDHE-ECDSA-AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH',
        'authentication': 'ECDSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-ECDSA-AES256-SHA': {
        'id': '0xC00A',
        'tls_name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        'openssl_name': 'ECDHE-ECDSA-AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH',
        'authentication': 'ECDSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'ECDH-RSA-RC4-SHA': {
        'id': '0xC00C',
        'tls_name': 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
        'openssl_name': 'ECDH-RSA-RC4-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH/RSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'RC4(128)',
        'message_authentication_code': 'SHA1'
    },
    'ECDH-RSA-DES-CBC3-SHA': {
        'id': '0xC00D',
        'tls_name': 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'ECDH-RSA-DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH/RSA',
        'authentication': 'ECDH',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'ECDH-RSA-AES128-SHA': {
        'id': '0xC00E',
        'tls_name': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
        'openssl_name': 'ECDH-RSA-AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH/RSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'ECDH-RSA-AES256-SHA': {
        'id': '0xC00F',
        'tls_name': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
        'openssl_name': 'ECDH-RSA-AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH/RSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-RSA-RC4-SHA': {
        'id': '0xC011',
        'tls_name': 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
        'openssl_name': 'ECDHE-RSA-RC4-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH',
        'authentication': 'RSA',
        'encryption_algorithm': 'RC4(128)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-RSA-DES-CBC3-SHA': {
        'id': '0xC012',
        'tls_name': 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
        'openssl_name': 'ECDHE-RSA-DES-CBC3-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH',
        'authentication': 'RSA',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-RSA-AES128-SHA': {
        'id': '0xC013',
        'tls_name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        'openssl_name': 'ECDHE-RSA-AES128-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-RSA-AES256-SHA': {
        'id': '0xC014',
        'tls_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        'openssl_name': 'ECDHE-RSA-AES256-SHA',
        'version': 'SSLv3',
        'key_exchange': 'ECDH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-3DES-EDE-CBC-SHA': {
        'id': '0xC01A',
        'tls_name': 'None',
        'openssl_name': 'SRP-3DES-EDE-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'SRP',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-RSA-3DES-EDE-CBC-SHA': {
        'id': '0xC01B',
        'tls_name': 'None',
        'openssl_name': 'SRP-RSA-3DES-EDE-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'RSA',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-DSS-3DES-EDE-CBC-SHA': {
        'id': '0xC01C',
        'tls_name': 'None',
        'openssl_name': 'SRP-DSS-3DES-EDE-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'DSS',
        'encryption_algorithm': '3DES(168)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-AES-128-CBC-SHA': {
        'id': '0xC01D',
        'tls_name': 'None',
        'openssl_name': 'SRP-AES-128-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'SRP',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-RSA-AES-128-CBC-SHA': {
        'id': '0xC01E',
        'tls_name': 'None',
        'openssl_name': 'SRP-RSA-AES-128-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-DSS-AES-128-CBC-SHA': {
        'id': '0xC01F',
        'tls_name': 'None',
        'openssl_name': 'SRP-DSS-AES-128-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'DSS',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-AES-256-CBC-SHA': {
        'id': '0xC020',
        'tls_name': 'None',
        'openssl_name': 'SRP-AES-256-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'SRP',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-RSA-AES-256-CBC-SHA': {
        'id': '0xC021',
        'tls_name': 'None',
        'openssl_name': 'SRP-RSA-AES-256-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'SRP-DSS-AES-256-CBC-SHA': {
        'id': '0xC022',
        'tls_name': 'None',
        'openssl_name': 'SRP-DSS-AES-256-CBC-SHA',
        'version': 'SSLv3',
        'key_exchange': 'SRP',
        'authentication': 'DSS',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA1'
    },
    'ECDHE-ECDSA-AES128-SHA256': {
        'id': '0xC023',
        'tls_name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'ECDHE-ECDSA-AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH',
        'authentication': 'ECDSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'ECDHE-ECDSA-AES256-SHA384': {
        'id': '0xC024',
        'tls_name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        'openssl_name': 'ECDHE-ECDSA-AES256-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH',
        'authentication': 'ECDSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA384'
    },
    'ECDH-ECDSA-AES128-SHA256': {
        'id': '0xC025',
        'tls_name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'ECDH-ECDSA-AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH/ECDSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'ECDH-ECDSA-AES256-SHA384': {
        'id': '0xC026',
        'tls_name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
        'openssl_name': 'ECDH-ECDSA-AES256-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH/ECDSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA384'
    },
    'ECDHE-RSA-AES128-SHA256': {
        'id': '0xC027',
        'tls_name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'ECDHE-RSA-AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'ECDHE-RSA-AES256-SHA384': {
        'id': '0xC028',
        'tls_name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        'openssl_name': 'ECDHE-RSA-AES256-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA384'
    },
    'ECDH-RSA-AES128-SHA256': {
        'id': '0xC029',
        'tls_name': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
        'openssl_name': 'ECDH-RSA-AES128-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH/RSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AES(128)',
        'message_authentication_code': 'SHA256'
    },
    'ECDH-RSA-AES256-SHA384': {
        'id': '0xC02A',
        'tls_name': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
        'openssl_name': 'ECDH-RSA-AES256-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH/RSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AES(256)',
        'message_authentication_code': 'SHA384'
    },
    'ECDHE-ECDSA-AES128-GCM-SHA256': {
        'id': '0xC02B',
        'tls_name': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'ECDHE-ECDSA-AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH',
        'authentication': 'ECDSA',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'ECDHE-ECDSA-AES256-GCM-SHA384': {
        'id': '0xC02C',
        'tls_name': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'ECDHE-ECDSA-AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH',
        'authentication': 'ECDSA',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'ECDH-ECDSA-AES128-GCM-SHA256': {
        'id': '0xC02D',
        'tls_name': 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'ECDH-ECDSA-AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH/ECDSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'ECDH-ECDSA-AES256-GCM-SHA384': {
        'id': '0xC02E',
        'tls_name': 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'ECDH-ECDSA-AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH/ECDSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'ECDHE-RSA-AES128-GCM-SHA256': {
        'id': '0xC02F',
        'tls_name': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'ECDHE-RSA-AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'ECDHE-RSA-AES256-GCM-SHA384': {
        'id': '0xC030',
        'tls_name': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'ECDHE-RSA-AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH',
        'authentication': 'RSA',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'ECDH-RSA-AES128-GCM-SHA256': {
        'id': '0xC031',
        'tls_name': 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
        'openssl_name': 'ECDH-RSA-AES128-GCM-SHA256',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH/RSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    },
    'ECDH-RSA-AES256-GCM-SHA384': {
        'id': '0xC032',
        'tls_name': 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
        'openssl_name': 'ECDH-RSA-AES256-GCM-SHA384',
        'version': 'TLSv1.2',
        'key_exchange': 'ECDH/RSA',
        'authentication': 'ECDH',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'TLS_AES_256_GCM_SHA384': {
        'id': '0x1302',
        'tls_name': 'TLS_AES_256_GCM_SHA384',
        'openssl_name': 'TLS_AES_256_GCM_SHA384',
        'version': 'TLSv1.3',
        'key_exchange': 'any',
        'authentication': 'any',
        'encryption_algorithm': 'AESGCM(256)',
        'message_authentication_code': 'AEAD'
    },
    'TLS_CHACHA20_POLY1305_SHA256': {
        'id': '0x1303',
        'tls_name': 'TLS_CHACHA20_POLY1305_SHA256',
        'openssl_name': 'TLS_CHACHA20_POLY1305_SHA256',
        'version': 'TLSv1.3',
        'key_exchange': 'any',
        'authentication': 'any',
        'encryption_algorithm': 'CHACHA20/POLY1305(256)',
        'message_authentication_code': 'AEAD'
    },
    'TLS_AES_128_GCM_SHA256': {
        'id': '0x1301',
        'tls_name': 'TLS_AES_128_GCM_SHA256',
        'openssl_name': 'TLS_AES_128_GCM_SHA256',
        'version': 'TLSv1.3',
        'key_exchange': 'any',
        'authentication': 'any',
        'encryption_algorithm': 'AESGCM(128)',
        'message_authentication_code': 'AEAD'
    }
}


def int_to_bytes(data: int, length):
    return data.to_bytes(length, 'big')


def prf_legacy(secret, label, seed, output_length):
    l_s = len(secret)
    l_s1 = l_s2 = math.ceil(l_s / 2)
    s1 = secret[:l_s1]
    s2 = secret[l_s1:]
    # assert l_s1 == l_s2, 'Odd length, inspect this case'

    _md5 = _prf(s1, label, seed, signature_algorithms.MD5(), output_length)
    _sha1 = _prf(s2, label, seed, signature_algorithms.SHA1(), output_length)

    _md5int = int.from_bytes(_md5, 'big')
    _sha1int = int.from_bytes(_sha1, 'big')
    xor = _md5int ^ _sha1int
    return xor.to_bytes(output_length, 'big')


def prf(tls_version: TLS, algorithm, secret, label, seed, output_length):
    if tls_version >= TLSv1_2():
        algorithm = algorithm if algorithm.digest_size >= 32 else signature_algorithms.SHA256()
        return _prf(secret, label, seed, algorithm, output_length)
    else:
        return prf_legacy(secret, label, seed, output_length)


class CipherSuite:
    def __init__(self, tls_version: TLS, cipher_suite: Dict[str, Any]):
        self.tls_version            = tls_version
        self.properties             = cipher_suite.copy()
        self._key_exchange          = cipher_suite.get("key_exchange")
        self.authentication         = cipher_suite.get("authentication")
        self._encryption_algorithm  = cipher_suite.get("encryption_algorithm")
        self.key_material_bits      = cipher_suite.get("key_material_bits")
        self.message_authentication_code = cipher_suite.get("message_authentication_code")

        #ke = cipher_suite['key_exchange'].split('/')
        #args = [tls_version, client_random, server_random, server_cert, ke[1] if len(ke) > 1 else None]
        #self._key_exchange: key_exchange.KeyExchange = getattr(key_exchange, ke[0])(*args)
        self.keys = dict()

    def __str__(self):
        return self.properties['openssl_name']  # TODO: Improve this


    def version_to_tls(version: str) -> Union[TLS, None]:
        return {
            "TLSv1.0": TLSv1(),
            "TLSv1.1": TLSv1_1(),
            "TLSv1.2": TLSv1_2(),
            "TLSv1.3": TLSv1_3()
        }.get(version, None)

    @staticmethod
    def get_cipher_suites_by_version(version: TLS, excluded: Optional[Iterable[TLSKeyExchangeTypes]] = None) -> CipherSuiteDict:
        """ Return suites supported by a TLS version """
        excluded = excluded or []

        # TODO: Comparison below is not really valid.  In TLSv1.3, some older suites were deprecated
        if isinstance(version, TLSv1_3):
            raise NotImplementedError("v1.3 is not yet supported, see comment above")

        results = {k: v for k, v in CIPHER_SUITES.items()
                   if v["version"] and v["version"] <= version and
                   all(dont_want !=  v["key_exchange"] for dont_want in excluded)}

        return deepcopy(results)

    @property
    def key_exchange_type(self) -> TLSKeyExchangeTypes:
        return self._key_exchange

    @property
    def security_parameters(self):
        enc_algo_class = self.properties.get('encryption_algorithm')
        sp = {
            'key_material_length': self.properties.get('key_material_bits') // 8,
        }
        if self.properties.get('message_authentication_code') == TLSMACAlgorithm.HMAC_AEAD:
            sp['hash_size'] = 0
            sp['IV_size'] = 4
        else:
            sp['hash_size'] = self.signature_algorithm.digest_size
            sp['IV_size'] = 16
        return sp

    @classmethod
    def get_from_id(cls, tls_version, ident):
        cipher = CIPHER_SUITES.get(ident)
        return CipherSuite(tls_version, cipher) if cipher else None

    @property
    def pre_master_secret(self):
        raise ValueError('pre_master_secret is not obtainable.')

    @pre_master_secret.setter
    def pre_master_secret(self, value):
        self._derive_key(value)

    @property
    def signature_algorithm(self):
        # name = self.properties.get('message_authentication_code')
        # if name == 'AEAD':
        #     openssl_name = self.properties.get('openssl_name')
        #     name = openssl_name[openssl_name.rfind('-')+1:]
        #     name = 'SHA1' if name == 'SHA' else name
        # return getattr(signature_algorithms, name)()
        return None
        # if self.tls_version >= TLSv1_2():
        #
        #     signature_algorithm = signature_algorithms.SignatureAlgorithm.get_by_code(
        #            #    frame[offset], self.server_cert.public_key()), data_bytes[2:]
        # else:
        #     signature_algorithm = signature_algorithms.RsaPkcs1Md5Sha1(self.server_certificate.public_key())

    @property
    def encryption_algorithm(self) -> 'encryption_algorithms.EncryptionAlgorithm':
        # text = self.properties.get('encryption_algorithm')
        # assert text.find('AES') > -1, NotImplementedError('Not support {}'.format(text))
        # text = text.split('(')
        # return getattr(encryption_algorithms, text[0])()
        return self._encryption_algorithm

    def parse_key_exchange_params(self, params_bytes):
        self.key_exchange.parse_params(params_bytes)

    def prf(self, secret, label, seed, output_length):
        return prf(self.tls_version, self.signature_algorithm, secret, label, seed, output_length)

    def _derive_key(self, value):
        master_secret = self.prf(value, b'master secret', self.client_random + self.server_random, 48)

        # key_block
        kb = self.prf(master_secret, b'key expansion', self.server_random + self.client_random, 200)

        keys, sp = {}, self.security_parameters

        keys['master_secret'] = master_secret
        keys['client_write_mac_key'], kb = kb[:sp['hash_size']], kb[sp['hash_size']:]
        keys['server_write_mac_key'], kb = kb[:sp['hash_size']], kb[sp['hash_size']:]
        keys['client_write_key'], kb = kb[:sp['key_material_length']], kb[sp['key_material_length']:]
        keys['server_write_key'], kb = kb[:sp['key_material_length']], kb[sp['key_material_length']:]
        keys['client_write_iv'], kb = kb[:sp['IV_size']], kb[sp['IV_size']:]
        keys['server_write_iv'], kb = kb[:sp['IV_size']], kb[sp['IV_size']:]

        self.keys = keys

    def encrypt(self, content_bytes, *, seq_num, content_type, encrypt_from='client'):
        iv = self.keys['{}_write_iv'.format(encrypt_from)]
        args = [self.tls_version, self.keys['{}_write_key'.format(encrypt_from)], iv, content_bytes]

        seq_bytes = int_to_bytes(seq_num, 8)
        additional_bytes = seq_bytes + content_type + self.tls_version

        kwargs = {
            'add': additional_bytes,
            'hash_algorithm': self.signature_algorithm,
            'sign_key': self.keys['{}_write_mac_key'.format(encrypt_from)]
        }
        return self.encryption_algorithm.encrypt(*args, **kwargs)

    def decrypt(self, encrypted_bytes, *, seq_num, content_type, decrypt_from='server'):
        key = self.keys['{}_write_key'.format(decrypt_from)]
        seq_bytes = int_to_bytes(seq_num, 8)
        additional_bytes = seq_bytes + content_type + self.tls_version

        kwargs = {
            'iv': self.keys['{}_write_iv'.format(decrypt_from)],
            'tls_version': self.tls_version,
            'key': key,
            'encrypted': encrypted_bytes,
            'add': additional_bytes,
            'hash_algorithm': self.signature_algorithm,
            'sign_key': self.keys['{}_write_mac_key'.format(decrypt_from)]
        }

        return self.encryption_algorithm.decrypt(**kwargs)

    def sign_verify_data(self, message):
        data = self.hash_verify_data(message)
        return self.prf(self.keys.get('master_secret'), constants.LABEL_CLIENT_FINISHED, data, 12)

    def verify_verify_data(self, message, signature):
        data = self.hash_verify_data(message)
        generated = self.prf(self.keys.get('master_secret'), constants.LABEL_SERVER_FINISHED, data, 12)
        assert signature == generated, ValueError('Signature incorrect')

    def hash_verify_data(self, message):
        if self.tls_version < TLSv1_2():
            algorithm = signature_algorithms.MD5SHA1()
        else:
            algorithm = self.signature_algorithm
            if algorithm.digest_size < 32:
                algorithm = signature_algorithms.SHA256()
        hash = signature_algorithms.Hash(algorithm, signature_algorithms.default_backend())
        hash.update(message)
        return hash.finalize()


