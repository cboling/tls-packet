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


# from pkt import DecodeError, SerializeError

from tls_packet.packet import Packet


class HelloExtension(Packet):
    """
    Hello Extensions

   A number of TLS messages contain tag-length-value encoded extensions
   structures.
        struct {
            ExtensionType extension_type;
            opaque extension_data<0..2^16-1>;
        } Extension;

        enum {
            server_name(0),
            max_fragment_length(1),
            status_request(5),
            supported_groups(10),
            signature_algorithms(13),
            use_srtp(14),
            heartbeat(15),
            application_layer_protocol_negotiation(16), /* RFC 7301 */
            signed_certificate_timestamp(18),
            client_certificate_type(19),
            server_certificate_type(20),
            padding(21),
            pre_shared_key(41),
            early_data(42),
            supported_versions(43),
            cookie(44),
            psk_key_exchange_modes(45),
            certificate_authorities(47),
            oid_filters(48),
            post_handshake_auth(49),
            signature_algorithms_cert(50),
            key_share(51),
            (65535)
        } ExtensionType;

        The table below indicates the messages where a given extension may
        appear, using the following notation: CH (ClientHello),
        SH (ServerHello), EE (EncryptedExtensions), CT (Certificate),
        CR (CertificateRequest), NST (NewSessionTicket), and
        HRR (HelloRetryRequest).  If an implementation receives an extension
        which it recognizes and which is not specified for the message in
        which it appears, it MUST abort the handshake with an
        "illegal_parameter" alert.

        +--------------------------------------------------+-------------+
        | Extension                                        | TLS 1.3     |
        +--------------------------------------------------+-------------+
        | server_name [RFC6066]                            | CH, EE      |
        | max_fragment_length [RFC6066]                    | CH, EE      |
        | status_request [RFC6066]                         | CH, CR, CT  |
        | supported_groups [RFC7919]                       | CH, EE      |
        | signature_algorithms (RFC 8446)                  | CH, CR      |
        | use_srtp [RFC5764]                               | CH, EE      |
        | heartbeat [RFC6520]                              | CH, EE      |
        | application_layer_protocol_negotiation [RFC7301] | CH, EE      |
        | signed_certificate_timestamp [RFC6962]           | CH, CR, CT  |
        | client_certificate_type [RFC7250]                | CH, EE      |
        | server_certificate_type [RFC7250]                | CH, EE      |
        | padding [RFC7685]                                | CH          |
        | key_share (RFC 8446)                             | CH, SH, HRR |
        | pre_shared_key (RFC 8446)                        | CH, SH      |
        | psk_key_exchange_modes (RFC 8446)                | CH          |
        | early_data (RFC 8446)                            | CH, EE, NST |
        | cookie (RFC 8446)                                | CH, HRR     |
        | supported_versions (RFC 8446)                    | CH, SH, HRR |
        | certificate_authorities (RFC 8446)               | CH, CR      |
        | oid_filters (RFC 8446)                           | CR          |
        | post_handshake_auth (RFC 8446)                   | CH          |
        | signature_algorithms_cert (RFC 8446)             |  CH, CR     |
        +--------------------------------------------------+-------------+

       struct {
           ExtensionType extension_type;
           opaque extension_data<0..2^16-1>;
       } Extension;

       enum {
           signature_algorithms(13), (65535)
       } ExtensionType;

       enum{
           none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
           sha512(6), (255)
       } HashAlgorithm;
       enum {
          anonymous(0), rsa(1), dsa(2), ecdsa(3), (255)
       } SignatureAlgorithm;

       struct {
             HashAlgorithm hash;
             SignatureAlgorithm signature;
       } SignatureAndHashAlgorithm;

       SignatureAndHashAlgorithm
        supported_signature_algorithms<2..2^16-1>;
    """

    def __init__(self, header: int, data: bytes):
        self.header = header
        self.data = data

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> "HelloExtension":
        raise NotImplementedError("TODO: Not yet implemented")

    def pack(self) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented")

    def __bytes__(self) -> bytes:
        return self.pack()
