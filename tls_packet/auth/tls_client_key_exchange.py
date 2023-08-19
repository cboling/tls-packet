import struct
from typing import Union, Optional

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

class TLSClientKeyExchange(TLSHandshake):
    """
      from https://wiki.osdev.org/TLS_Handshake#Certificate_Message

      TLS encryption is performed using symmetric encryption. The client and server thus need to
      agree on a secret key. This is done in the key exchange protocol.

      In our example, TLS is using the DHE/RSA algorithms: the Diffie-Hellman Ephemeral protocol
      is used to come up with the secret key, and the server is using the RSA protocol to sign
      the numbers it sends to the client (the signature is linked to its SSL certificate) to
      ensure that a third party cannot inject a malicious number. The upside of DHE is that it
      is using a temporary key that will be discarded afterwards. Key exchange protocols such
      as DH or RSA are using numbers from the SSL certificate. As a result, a leak of the
      server's private key (for example through Heartbleed) means that a previously recorded
      SSL/TLS encryption can be decrypted. Ephemeral key exchange protocols such as DHE or ECDHE
      offer so-called forward secrecy and are safe even if the server's private key is later
      compromised.

        Diffie-Hellman Ephemeral works as follows:

            The server comes up with a secret number y, with a number g and a modulo p (p typically
            being a 1024 bit integer) and sends (p, g, pubKey=gy mod p) to the client in its
            "Server Key Exchange" message. It also sends a signature of the Diffie-Hellman parameters
            (see SSL Certificate section)

            The client comes up with a secret number x and sends pubKey=gx mod p to the server in its
            "Client Key Exchange" message

            The client and server derive a common key premaster_secret = (gx)y mod p = (gy)x mod p = gxy mod p.
            If p is large enough, it is extremely hard for anyone knowing only gx and gy (which were
            transmitted in clear) to find that key.

            Because computing gxy mod p using 1024-bytes integers can be tedious in most programming
            languages, if security is not a concern, one way to avoid this is to use x=1. This way,
            premaster_secret is just gy mod p, a value directly sent by the server. The security in
            such a case is of course compromised.

            premaster_key is however only a first step. Both client and server uses the PRF function
            to come up with a 48-byte master secret. The PRF function is used once again to generate
            a 104-bytes series of data which will represent all the secret keys used in the
            conversation (the length may differ depending on the cipher suite used):

                # g_y, g and p are provided in the Server Key Exchange message
                # The client determines x
                premaster_secret = pow(g_y, x, p)

            # client_random and sever_random are the 32-bytes random data from the Client Hello
            and Server Hello messages

                master_secret = PRF(premaster_secret, "master secret", client_random + server_random, 48)
                keys = PRF(master_secret, "key expansion", server_random + client_random, 104)

            # The MAC keys are 20 bytes because we are using HMAC+SHA1
                client_write_MAC_key = keys[0:20]
                server_write_MAC_key = keys[20:40]

            # The client and server keys are 16 bytes because we are using AES 128-bit aka
              a 128 bit = 16 bytes key
                client_write_key = keys[40:56]
                server_write_key = keys[56:72]

            # The IVs are always 16 bytes because AES encrypts blocks of 16 bytes
                client_write_IV = keys[72:88]
                server_write_IV = keys[88:104]

                Note how different secret keys are used for the client and for the server, as well
                as for encryption and to compute the MAC.

        -----------------------------------------------------------------------------

        Client Key Exchange Message
            The client then sends its key exchange parameters: pubKey=gx

            0x10: handshake type=client key exchange
            0x000102: length=258
            0x0100: pubKey length=256
            ...: 256-bytes pubKey
            Change Cipher Spec Message

            The client sends the Change Cipher Spec message to indicate it has completed its
            part of the handshake. The next message the server will expect is the Encrypted Handshake Message.

            The whole message (including the TLS Record header) is 6 bytes long:

            typedef struct __attribute__((packed)) {
                uint8_t content_type;   // 0x14
                uint16_t version;       // 0x0303 for TLS 1.2
                uint8_t length;         // 0x01
                uint8_t content;        // 0x01

            } TLSChangeCipherSpec;

        -----------------------------------------------------------------------------

        Encrypted Handshake Message
            The TLS handshake is concluded with the two parties sending a hash of the complete
            handshake exchange, in order to ensure that a middleman did not try to conduct a
            downgrade attack.

            If your TLS client technically does not have to verify the Encrypted Handshake
            Message sent by the server, it needs to send a valid Encrypted Handshake Message
            of its own, otherwise the server will abort the TLS session.

            Here is what the client needs to do to create :

            Compute a SHA256 hash of a concatenation of all the handshake communications (or
            SHA384 if the PRF is based on SHA384). This means the Client Hello, Server Hello,
            Certificate, Server Key Exchange, Server Hello Done and Client Key Exchange
            messages. Note that you should concatenate only the handshake part of each TLS
            message (i.e. strip the first 5 bytes belonging to the TLS Record header)

            Compute PRF(master_secret, "client finished", hash, 12) which will generate a
            12-bytes hash

            Append the following header which indicates the hash is 12 bytes: 0x14 0x00 0x00 0x0C

            Encrypt the 0x14 0x00 0x00 0x0C | [12-bytes hash] (see the Encrypting / Decrypting
            data section). This will generate a 64-bytes ciphertext using AES-CBC and 40 bytes
            with AES-GCM

            Send this ciphertext wrapped in a TLS Record
            The server will use a similar algorithm, with two notable differences:

            It needs to compute a hash of the same handshake communications as the client as
            well as the decrypted "Encrypted Handshake Message" message sent by the client
            (i.e. the 16-bytes hash starting with 0x1400000C)

            It will call PRF(master_secret, "server finished", hash, 12)

    """

    def __init__(self, curve_type: [ECCurveType], named_curve: [NamedCurve],
                 public_key: bytes, signature: bytes, *args, **kwargs):
        super().__init__(TLSHandshakeType.SERVER_KEY_EXCHANGE, *args, **kwargs)

        self._curve_type = curve_type
        self._named_curve = named_curve
        self._public_key = public_key
        self._signature = signature

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        """ Frame to TLSServerKeyExchange """

        # type(1) + length(3) + curve_type(1) + named_curve(2) + pubkey len (1) + pubkey (0..n) + signature len (2) + signature (0..n)
        required = 1 + 3 + 1 + 2 + 1 + 2
        frame_len = len(frame)

        if frame_len < required:
            raise DecodeError(f"TLSServerKeyExchange: message truncated: Expected at least {required} bytes, got: {frame_len}")

        msg_type = TLSHandshakeType(frame[0])
        if msg_type != TLSHandshakeType.SERVER_KEY_EXCHANGE:
            raise DecodeError(f"TLSServerKeyExchange: Message type is not SERVER_KEY_EXCHANGE. Found: {msg_type}")

        msg_len = int.from_bytes(frame[1:4], 'big')
        frame = frame[:msg_len + 4]  # Restrict the frame to only these bytes

        curve_type = ECCurveType(frame[4])
        named_curve = NamedCurve(struct.unpack_from("!H", frame, 5)[0])

        pubkey_len = frame[7]
        offset = 8
        if offset + pubkey_len + 2 > len(frame):
            raise DecodeError("TLSServerKeyExchange: message truncated. Unable to extract public key and/or signature length")

        pubkey = frame[offset:offset + pubkey_len]
        offset += pubkey_len

        sig_len = struct.unpack_from("!H", frame, offset)[0]
        offset += 2
        if offset + sig_len > len(frame):
            raise DecodeError("TLSServerKeyExchange: message truncated. Unable to extract signature")

        signature = frame[offset:offset + sig_len]

        return TLSServerKeyExchange(curve_type, named_curve, pubkey, signature, *args, length=msg_len, original_frame=frame, **kwargs)

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
