from typing import Union, Optional

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

    def __init__(self, *args, **kwargs):
        super().__init__(TLSHandshakeType.CERTIFICATE_VERIFY, *args, **kwargs)

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSCertificateRequest """

        # type(1) + length(3) + cert-count(1) + certs(0..n) + DSN len (1) + dsn (0..n)
        required = 1 + 3 + 1 + 1
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSCertificateRequest: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.CERTIFICATE_VERIFY:
            raise DecodeError(f"TLSCertificateRequest: Message type is not CERTIFICATE_VERIFY. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')
        frame = frame[:msg_len + 4]  # Restrict the frame to only these bytes

        return TLSCertificateVerify(*args, length=msg_len, original_frame=frame, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
