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
from typing import Union, Optional

from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import DecodeError, PARSE_ALL


class TLSCertificateVerify(TLSHandshake):
    """
    TLS Certificate Verify Message

        This message is used to provide explicit verification of a client
        certificate.  This message is only sent following a client
        certificate that has signing capability (i.e., all certificates
        except those containing fixed Diffie-Hellman parameters).  When
        sent, it MUST immediately follow the client key exchange message.

          struct {
               digitally-signed struct {
                   opaque handshake_messages[handshake_messages_length];
               }
          } CertificateVerify;

        Here handshake_messages refers to all handshake messages sent or
        received, starting at client hello and up to, but not including,
        this message, including the type and length fields of the
        handshake messages.  This is the concatenation of all the
        Handshake structures (as defined in Section 7.4) exchanged thus
        far.  Note that this requires both sides to either buffer the
        messages or compute running hashes for all potential hash
        algorithms up to the time of the CertificateVerify computation.
        Servers can minimize this computation cost by offering a
        restricted set of digest algorithms in the CertificateRequest
        message.

        The hash and signature algorithms used in the signature MUST be
        one of those present in the supported_signature_algorithms field
        of the CertificateRequest message.  In addition, the hash and
        signature algorithms MUST be compatible with the key in the
        client's end-entity certificate.  RSA keys MAY be used with any
        permitted hash algorithm, subject to restrictions in the
        certificate, if any.

        Because DSA signatures do not contain any secure indication of
        hash algorithm, there is a risk of hash substitution if multiple
        hashes may be used with any key.  Currently, DSA [DSS] may only be
        used with SHA-1.  Future revisions of DSS [DSS-3] are expected to
        allow the use of other digest algorithms with DSA, as well as
        guidance as to which digest algorithms should be used with each
        key size.  In addition, future revisions of [PKIX] may specify
        mechanisms for certificates to indicate which digest algorithms
        are to be used with DSA.
    """

    def __init__(self, signature: Optional[bytes] = None, **kwargs):
        super().__init__(TLSHandshakeType.CERTIFICATE_VERIFY, **kwargs)
        self._signature = signature

    @property
    def signature(self) -> bytes:
        return self._signature

    @staticmethod
    def create(data_so_far: bytes, security_params: 'SecurityParamters') -> bytes:
        signature = b""

        server_certificate = security_params.server_certificate
        server_public_key = security_params.server_public_key

        client_public_key = security_params.client_public_key
        client_private_key = security_params.client_private_key

        key_exchange_type = security_params.cipher_suite.key_exchange_type
        signature = b""

        TLSCertificateVerify(signature)

        # certificate = self.session.certificate.tbs_certificate_bytes if self.session.certificate is not None else b''
        # ca_certificate = self.session.ca_certificate.tbs_certificate_bytes if self.session.ca_certificate is not None else b''
        # pub_cert = ASN_1_Cert(certificate)
        # ca_cert = ASN_1_Cert(ca_certificate)  # TODO: Need to support a list?
        # cert_list = ASN_1_CertList([pub_cert, ca_cert])

    @staticmethod
    def parse(frame: bytes, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSCertificateRequest """

        # type(1) + length(3) + sig_len(2)
        required = 1 + 3 + 2
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSCertificateRequest: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.CERTIFICATE_VERIFY:
            raise DecodeError(f"TLSCertificateRequest: Message type is not CERTIFICATE_VERIFY. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')
        sig_len = int.from_bytes(frame[4:6], 'big')

        sig_frame = frame[6:]
        if len(sig_frame) < sig_len:
            raise DecodeError(f"TLSCertificateRequest: message sinature truncated: Expected at least {sig_len} bytes, got: {len(sig_frame)}")

        return TLSCertificateVerify(signature=sig_frame, original_frame=frame, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        # sig_len = struct.pack("!H", len(self._signature))
        sig_len = struct.pack("!H", len(self._signature))
        sig_buffer = sig_len + self._signature

        return super().pack(payload=sig_buffer)
