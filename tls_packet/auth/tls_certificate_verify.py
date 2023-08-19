from typing import Union, Optional

from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.packet import DecodeError, PARSE_ALL


class TLSCertificateVerify(TLSHandshake):
    """
    TLS Certificate Verify Message
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
