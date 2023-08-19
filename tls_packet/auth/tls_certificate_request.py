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

from enum import IntEnum
from typing import Union, Optional, List

from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import DecodeError, PARSE_ALL


# https://www.ietf.org/rfc/rfc5246.txt
#
#             The Transport Layer Security (TLS) Protocol
#                            Version 1.2
#
# Handshake Protocol
#
#      Client                                               Server
#
#      ClientHello                  -------->
#                                                      ServerHello
#                                                     Certificate*
#                                               ServerKeyExchange*
#                                              CertificateRequest*
#                                   <--------      ServerHelloDone
#      Certificate*
#      ClientKeyExchange
#      CertificateVerify*
#      [ChangeCipherSpec]
#      Finished                     -------->
#                                               [ChangeCipherSpec]
#                                   <--------             Finished
#      Application Data             <------->     Application Data
#
#    The TLS Handshake Protocol is one of the defined higher-level clients
#    of the TLS Record Protocol.  This protocol is used to negotiate the
#    secure attributes of a session.  Handshake messages are supplied to
#    the TLS record layer, where they are encapsulated within one or more
#    TLSPlaintext structures, which are processed and transmitted as
#    specified by the current active session state.


class CertificateType(IntEnum):
    """
      enum {
          rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
          rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
          fortezza_dms_RESERVED(20), (255)
      } ClientCertificateType;
      # And was extended in RFC 8422
       enum {
           ecdsa_sign(64),
           deprecated1(65),  /* was rsa_fixed_ecdh */
           deprecated2(66),  /* was ecdsa_fixed_ecdh */
           (255)
       } ClientCertificateType;
    """
    RSA_SIGN = 1
    DSS_SIGN = 2
    RSA_FIXED_DH = 3
    DSS_FIXED_DH = 4
    RSA_EPHEMERAL_DH_RESERVED = 5
    DSS_EPHEMERAL_DH_RESERVED = 6
    FORTEZZA_DMS_RESERVED = 20
    ECDSA_SIGN = 64
    RSA_FIXED_ECDH = 65  # Deprecated
    ECDSA_FIXED_ECDH = 66  # Deprecated

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


class TLSCertificateRequest(TLSHandshake):
    """
    TLS Certificate Message

       A non-anonymous server can optionally request a certificate from
       the client, if appropriate for the selected cipher suite.  This
       message, if sent, will immediately follow the ServerKeyExchange
       message (if it is sent; otherwise, this message follows the
       server's Certificate message).

          enum {
              rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
              rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
              fortezza_dms_RESERVED(20), (255)
          } ClientCertificateType;

          opaque DistinguishedName<1..2^16-1>;

          struct {
              ClientCertificateType certificate_types<1..2^8-1>;
              SignatureAndHashAlgorithm
                supported_signature_algorithms<2^16-1>;
              DistinguishedName certificate_authorities<0..2^16-1>;
          } CertificateRequest;

       certificate_types
          A list of the types of certificate types that the client may
          offer.

             rsa_sign        a certificate containing an RSA key
             dss_sign        a certificate containing a DSA key
             rsa_fixed_dh    a certificate containing a static DH key.
             dss_fixed_dh    a certificate containing a static DH key


       supported_signature_algorithms
          A list of the hash/signature algorithm pairs that the server is
          able to verify, listed in descending order of preference.

       certificate_authorities
          A list of the distinguished names [X501] of acceptable
          certificate_authorities, represented in DER-encoded format.  These
          distinguished names may specify a desired distinguished name for a
          root CA or for a subordinate CA; thus, this message can be used to
          describe known roots as well as a desired authorization space.  If
          the certificate_authorities list is empty, then the client MAY
          send any certificate of the appropriate ClientCertificateType,
          unless there is some external arrangement to the contrary.
    """

    def __init__(self, certificate_types: List[CertificateType], dsn: bytes, *args, **kwargs):
        super().__init__(TLSHandshakeType.CERTIFICATE_REQUEST, *args, **kwargs)

        self._certificate_types = certificate_types
        self._dsn = dsn

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSCertificateRequest """

        # type(1) + length(3) + cert-count(1) + certs(0..n) + DSN len (1) + dsn (0..n)
        required = 1 + 3 + 1 + 1
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSCertificateRequest: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.CERTIFICATE_REQUEST:
            raise DecodeError(f"TLSCertificateRequest: Message type is not CERTIFICATE_REQUEST. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')
        frame = frame[:msg_len + 4]  # Restrict the frame to only these bytes

        cert_type_count = frame[4]
        offset = 5
        if offset + cert_type_count > len(frame):
            raise DecodeError("TLSServerKeyExchange: message truncated. Unable to extract certificate types")

        certificate_types = []
        for index in range(cert_type_count):
            certificate_types.append(CertificateType(frame[offset + index]))
        offset += cert_type_count

        dns_length = frame[offset]
        offset += 1

        if offset + dns_length > len(frame):
            raise DecodeError("TLSServerKeyExchange: message truncated. Unable to extract Distinguished Names")

        dsn = frame[offset:offset + dns_length]

        return TLSCertificateRequest(certificate_types, dsn, *args, length=msg_len, original_frame=frame, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
