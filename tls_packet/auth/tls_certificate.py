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
from typing import Union, Optional, List, Tuple

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

class ITUX509Cert:
    """
    From T-REC-X509-201910

        7.2.1	Public-key certificate syntax
    A CA issues a public-key certificate of an entity by digital signing (see clause 6.1) a collection of information, including its distinguished name, the entity's distinguished name, a validity period, the value of a public-key algorithm and public key, as well as an optional additional information like for the permitted usage of the user's public key. The following ASN.1 data type specifies the syntax of public-key certificates:

    Certificate ::= SIGNED{TBSCertificate}

    TBSCertificate ::= SEQUENCE {
      version                  [0]  Version DEFAULT v1,
      serialNumber                  CertificateSerialNumber,
      signature                     AlgorithmIdentifier{{SupportedAlgorithms}},
      issuer                        Name,
      validity                      Validity,
      subject                       Name,
      subjectPublicKeyInfo          SubjectPublicKeyInfo,
      issuerUniqueIdentifier   [1] IMPLICIT UniqueIdentifier OPTIONAL,
      ...,
      [[2: -- if present, version shall be v2 or v3
      subjectUniqueIdentifier  [2] IMPLICIT UniqueIdentifier OPTIONAL]],
      [[3: -- if present, version shall be v2 or v3
      extensions               [3]  Extensions OPTIONAL]]
      -- If present, version shall be v3]]
    }

    Version ::= INTEGER {v1(0), v2(1), v3(2)}

    CertificateSerialNumber ::= INTEGER

    Validity ::= SEQUENCE {
      notBefore  Time,
      notAfter   Time,
      ... }

    SubjectPublicKeyInfo ::= SEQUENCE {
      algorithm         AlgorithmIdentifier{{SupportedAlgorithms}},
      subjectPublicKey  BIT STRING,
      ... }

    Time ::= CHOICE {
      utcTime          UTCTime,
      generalizedTime  GeneralizedTime }

    Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension

    Extension ::= SEQUENCE {
      extnId     EXTENSION.&id({ExtensionSet}),
      critical   BOOLEAN DEFAULT FALSE,
      extnValue  OCTET STRING
        (CONTAINING EXTENSION.&ExtnType({ExtensionSet}{@extnId})
           ENCODED BY der),
      ... }

    der OBJECT IDENTIFIER ::=
      {joint-iso-itu-t asn1(1) ber-derived(2) distinguished-encoding(1)}

    ExtensionSet EXTENSION ::= {...}


    """

    def __init__(self, serial_number: int,
                 signature: 'rdnSequence',
                 issuer: 'AlgorithmIdentifier',
                 validity: Tuple['utcTime'],
                 subject: 'rdnSequence',
                 public_key_info: 'SubjectPublicKeyInfo',
                 issuer_unique_identifier: Optional['UniqueIdentifier'] = None,
                 subject_unique_identifier: Optional['UniqueIdentifier'] = None,
                 extensions: Optional['Extensions'] = None):
        pass
        """
    TBSCertificate ::= SEQUENCE {
      version                  [0]  Version DEFAULT v1,
      serialNumber                  CertificateSerialNumber,
      signature                     AlgorithmIdentifier{{SupportedAlgorithms}},
      issuer                        Name,
      validity                      Validity,
      subject                       Name,
      subjectPublicKeyInfo          SubjectPublicKeyInfo,
      issuerUniqueIdentifier   [1] IMPLICIT UniqueIdentifier OPTIONAL,
      ...,
      [[2: -- if present, version shall be v2 or v3
      subjectUniqueIdentifier  [2] IMPLICIT UniqueIdentifier OPTIONAL]],
      [[3: -- if present, version shall be v2 or v3
      extensions               [3]  Extensions OPTIONAL]]
      -- If present, version shall be v3]]
    }
     """


class ASN_1_Cert:
    """
    struct {
        opaque ASN.1Cert<1..length>;        # For now
    } ASN.1Cert
    """
    header_size = 3

    def __init__(self, data: bytes):
        # Error checks
        self._data = data

    @property
    def length(self) -> int:
        return len(self._data) if self._data else 0

    @property
    def certificate(self) -> bytes:
        return self._data

    @staticmethod
    def parse(frame: bytes) -> 'ASN_1_Cert':
        """ Frame to TLSSessionHello """
        required = 3
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"ASN.1Cert: message truncated: Expected at least {required} bytes, got: {frame_len}")

        length = int.from_bytes(frame[0:3], 'big')
        if frame_len < length:
            raise DecodeError(f"ASN.1Cert: message truncated: Certificate should be {required} bytes, only {frame_len} bytes left")

        # TODO: Eventually need a actual class here
        data = frame[ASN_1_Cert.header_size:length + ASN_1_Cert.header_size]
        return ASN_1_Cert(data)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")


class ASN_1_CertList:
    """
    struct {
        uint24_t    length;
        opaque ASN.1Cert<1..length>;        # For now
    } ASN.1Cert

    """
    header_size = 3

    def __init__(self, certificates: List['ASN_1_Cert']):
        # Error checks
        self._certificates = certificates

    @property
    def length(self) -> int:
        return sum(cert.length for cert in self._certificates) if self._certificates else 0

    @property
    def certificate_list(self) -> Tuple['ASN_1_Cert']:
        return tuple(self._certificates)

    @staticmethod
    def parse(frame: bytes) -> 'ASN_1_CertList':
        """ Frame to TLSSessionHello """
        required = 3
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"ASN.ASN_1_CertList: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_len = int.from_bytes(frame[0:3], 'big')
        if frame_len < msg_len:
            raise DecodeError(f"ASN.ASN_1_CertList: message truncated: Certificate List should be {required} bytes, only {frame_len} bytes left")

        certificates: List[ASN_1_Cert] = []
        offset = 3

        while offset < frame_len:
            certificate = ASN_1_Cert.parse(frame[offset:offset + msg_len])
            offset += certificate.length + certificate.header_size
            certificates.append(certificate)

        return ASN_1_CertList(certificates)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")


class TLSCertificate(TLSHandshake):
    """
    TLS Certificate Message

      The server MUST send a Certificate message whenever the agreed-
      upon key exchange method uses certificates for authentication
      (this includes all key exchange methods defined in this document
      except DH_anon).  This message will always immediately follow the
      ServerHello message.

          opaque ASN.1Cert<1..2^24-1>;

          struct {
              ASN.1Cert certificate_list<0..2^24-1>;
          } Certificate;

       certificate_list
          This is a sequence (chain) of certificates.  The sender's
          certificate MUST come first in the list.  Each following
          certificate MUST directly certify the one preceding it.  Because
          certificate validation requires that root keys be distributed
          independently, the self-signed certificate that specifies the root
          certificate authority MAY be omitted from the chain, under the
          assumption that the remote end must already possess it in order to
          validate it in any case.

        The server then sends a Certificate message containing its SSL Certificate chain. The first certificate
        is the server's SSL certificate. The next certificate is the certificate from a Certificate Authority (CA)
        which signed the first certificate. The next certificate signs the previous certificate, and so on. The last
        certificate in the chain should belong to a root CA and is self-signed (each TLS client should have a list
        of all the root CAs)

        Here is how the Certificate Message is encoded:

        0x0B: handshake type=Certificate
        0x000C58: length=3160
        0x000C55: certificates length=3157
        0x0007E2: certificate #1 Length=2018
        0x3082...C0F3: first certificate (ASN.1 encoded)
        0x00046D: certificate #2 length=1133
        0x3080...4998: second certificate (ASN.1 encoded)

    """

    def __init__(self, certificates: ASN_1_CertList, *args, **kwargs):
        super().__init__(TLSHandshakeType.CERTIFICATE, *args, **kwargs)

        self._certificates = certificates

    @property
    def certificates(self) -> Tuple[ASN_1_Cert]:
        return self._certificates.certificate_list

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSCertificate """
        required = 4
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSServerHello: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.CERTIFICATE:
            raise DecodeError(f"TLSSessionHello: Message type is not SERVER_HELLO. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')
        offset = 4

        certificates = ASN_1_CertList.parse(frame[offset:offset + msg_len])

        return TLSCertificate(certificates, length=msg_len, *args, **kwargs, original_frame=frame)  # TODO: later ->  , extensions = extensions)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        """
        Create a TLSCertificate packet
        """
        cert_buffer = b''
        for cert in self.certificates:
            cert_len = struct.pack("!I", cert.length)  # We only want 24-bits
            cert_buffer += cert_len[1:] + cert.certificate

        cert_len = struct.pack("!I", len(cert_buffer))  # We only want 24-bits
        buffer = cert_len[1:] + cert_buffer

        return super().pack(payload=buffer)
