// -------------------------------------------------------------------------
// Copyright 2023-2023, Boling Consulting Solutions, bcsw.net
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// -------------------------------------------------------------------------
//
// Program to generate available ciphers.  Python version of OpenSSL (cryptography)
// does not support "SSL_get_ciphers()"
//
//  Compile with:
//
//      g++ -o mk_cipher mk_cipher_list.c -lssl -lcrypto
//
#include <iostream>
#include <openssl/ssl.h>
#include <cstring>


struct ssl_cipher_st_2 {
    uint32_t valid;
    const char *name;           /* text name */
    const char *stdname;        /* RFC name */
    uint32_t id;                /* id, 4 bytes, first is version */
    /*
     * changed in 1.0.0: these four used to be portions of a single value
     * 'algorithms'
     */
    uint32_t algorithm_mkey;    /* key exchange algorithm */
    uint32_t algorithm_auth;    /* server authentication */
    uint32_t algorithm_enc;     /* symmetric encryption */
    uint32_t algorithm_mac;     /* symmetric authentication */
    int min_tls;                /* minimum SSL/TLS protocol version */
    int max_tls;                /* maximum SSL/TLS protocol version */
    int min_dtls;               /* minimum DTLS protocol version */
    int max_dtls;               /* maximum DTLS protocol version */
    uint32_t algo_strength;     /* strength and export flags */
    uint32_t algorithm2;        /* Extra flags */
    int32_t strength_bits;      /* Number of bits really used */
    uint32_t alg_bits;          /* Number of bits for algorithm */
};

const char* key_exchange(int kx_nid) {
    if (kx_nid == NID_kx_rsa)
        return "RSA";

    if (kx_nid == NID_kx_ecdhe)
        return "ECDHE";

    if (kx_nid == NID_kx_ecdhe_psk)
        return "ECDHE-PSK";

    if (kx_nid == NID_kx_dhe_psk)
        return "DHE-PSK";

    if (kx_nid == NID_kx_rsa_psk)
        return "RSA_PSK";

    if (kx_nid == NID_kx_dhe)
        return "DHE";

    if (kx_nid == NID_kx_psk)
        return "PSK";

    if (kx_nid == NID_kx_srp)
        return "SRP";

    if (kx_nid == NID_kx_gost)
        return "GOST";

    if (kx_nid == NID_kx_any)
        return "ANY";

    return "";
}


const char* authentication(int auth_nid) {
    if (auth_nid == NID_auth_rsa)
        return "RSA";

    if (auth_nid == NID_auth_ecdsa)
        return "ECDSA";

    if (auth_nid == NID_auth_psk)
        return "PSK";

    if (auth_nid == NID_auth_dss)
        return "DSS";

    if (auth_nid == NID_auth_gost01)
        return "GOST01";

    if (auth_nid == NID_auth_gost12)
        return "GOST12";

    if (auth_nid == NID_auth_srp)
        return "SRP";

    if (auth_nid == NID_auth_null)
        return "NULL";

    if (auth_nid == NID_auth_any)
        return "ANY";

    return "";
}

const char* msg_auth_code(int mac) {

    if (mac == NID_sha1)
        return SN_sha1;

    if (mac == NID_sha)
        return SN_sha;

    if (mac == NID_md5WithRSA)
        return SN_md5WithRSA;

    if (mac == NID_des_ecb)
        return SN_des_ecb;

    if (mac == NID_des_cbc)
        return SN_des_cbc;

    if (mac == NID_des_ofb64)
        return SN_des_ofb64;

    if (mac == NID_des_cfb64)
        return SN_des_cfb64;

    if (mac == NID_dsa_2)
        return SN_dsa_2;

    if (mac == NID_dsaWithSHA)
        return SN_dsaWithSHA;

    if (mac == NID_shaWithRSAEncryption)
        return SN_shaWithRSAEncryption;

    if (mac == NID_des_ede_ecb)
        return SN_des_ede_ecb;

    if (mac == NID_dsaWithSHA1_2)
        return SN_dsaWithSHA1_2;

    if (mac == NID_sha1WithRSA)
        return SN_sha1WithRSA;

    return "";
}


int main() {
    SSL_CTX* server_ctx(SSL_CTX_new(TLS_method()));
    SSL* ssl(SSL_new(server_ctx));
    STACK_OF(SSL_CIPHER)* cipher_list = SSL_get_ciphers(ssl);
    int last_index = sk_SSL_CIPHER_num(cipher_list) - 1;

    // Output is JSON
    std::cout << std::endl << "CIPHER_SUITES = {" << std::endl;

    for (int index = 0; index <= last_index ; ++index) {
        int algbits = 0;
        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(cipher_list, index);
        const char *version = SSL_CIPHER_get_version(cipher);

        if (strncmp(version, "SSL", 3) == 0) {
            continue;
        }
        uint16_t id = SSL_CIPHER_get_protocol_id(cipher);
        const char *name = SSL_CIPHER_get_name(cipher);
        const char *tls_name = SSL_CIPHER_standard_name(cipher);
        const int val5 = SSL_CIPHER_is_aead(cipher);
        const char* key_ex = key_exchange(SSL_CIPHER_get_kx_nid(cipher));
        const char* auth = authentication(SSL_CIPHER_get_auth_nid(cipher));
        const int bits = SSL_CIPHER_get_bits(cipher, &algbits);
        const struct ssl_cipher_st_2* xxx = (const struct ssl_cipher_st_2*)cipher;
        const char* msg_auth = msg_auth_code(xxx->algorithm_mac);

        std::cout << "    '" << name << "': {" << std::endl;
        std::cout << "        'id':             "  << id       << "," << std::endl;
        std::cout << "        'version':        '" << version  << "'," << std::endl;
        std::cout << "        'tls_name':       '" << tls_name << "'," << std::endl;
        std::cout << "        'key_exchange':   '" << key_ex   << "'," << std::endl;
        std::cout << "        'authentication': '" << auth     << "'," << std::endl;
        std::cout << "        'bits':           "  << bits     << "," << std::endl;
        std::cout << "        'mac':            '" << msg_auth << "'," << std::endl;
        std::cout << "    }";
        if (index != last_index) {
            std::cout << ",";
        }
        std::cout << std::endl;
    }
    std::cout << "}" << std::endl << std::endl;

    return 0;

}
