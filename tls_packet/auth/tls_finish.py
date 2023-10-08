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
from typing import Union, Optional

from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType


class TLSFinish(TLSHandshake):
    """
    TLS Finish Message
      when this message will be sent:

        A Finished message is always sent immediately after a change
        cipher spec message to verify that the key exchange and
        authentication processes were successful.  It is essential that a
        change cipher spec message be received between the other handshake
        messages and the Finished message.

     Meaning of this message:

        The Finished message is the first one protected with the just
        negotiated algorithms, keys, and secrets.  Recipients of Finished
        messages MUST verify that the contents are correct.  Once a side
        has sent its Finished message and received and validated the
        Finished message from its peer, it may begin to send and receive
        application data over the connection.

      struct {
          opaque verify_data[verify_data_length];
      } Finished;

      verify_data
         PRF(master_secret, finished_label, Hash(handshake_messages))
            [0..verify_data_length-1];

      finished_label
         For Finished messages sent by the client, the string
         "client finished".  For Finished messages sent by the server,
         the string "server finished".

      Hash denotes a Hash of the handshake messages.  For the PRF
      defined in Section 5, the Hash MUST be the Hash used as the basis
      for the PRF.  Any cipher suite which defines a different PRF MUST
      also define the Hash to use in the Finished computation.

      In previous versions of TLS, the verify_data was always 12 octets
      long.  In the current version of TLS, it depends on the cipher
      suite.  Any cipher suite which does not explicitly specify
      verify_data_length has a verify_data_length equal to 12.  This
      includes all existing cipher suites.  Note that this
      representation has the same encoding as with previous versions.
      Future cipher suites MAY specify other lengths but such length
      MUST be at least 12 bytes.

      handshake_messages
         All of the data from all messages in this handshake (not
         including any HelloRequest messages) up to, but not including,
         this message.  This is only data visible at the handshake layer
         and does not include record layer headers.  This is the
         concatenation of all the Handshake structures as defined in
         Section 7.4, exchanged thus far.

      It is a fatal error if a Finished message is not preceded by a
      ChangeCipherSpec message at the appropriate point in the handshake.

      The value handshake_messages includes all handshake messages starting
      at ClientHello up to, but not including, this Finished message.  This
      may be different from handshake_messages in Section 7.4.8 because it
      would include the CertificateVerify message (if sent).  Also, the
      handshake_messages for the Finished message sent by the client will
      be different from that for the Finished message sent by the server,
      because the one that is sent second will include the prior one.

      Note: ChangeCipherSpec messages, alerts, and any other record types
      are not handshake messages and are not included in the hash
      computations.  Also, HelloRequest messages are omitted from handshake
      hashes.


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

    def __init__(self, session):
        super().__init__(TLSHandshakeType.FINISHED)
        self._session = session
        raise NotImplementedError("TODO: just a cut&paste stub for now.  nowhere close to what it should be") \

    @staticmethod
    def parse(frame: bytes, **kwargs) -> Union[TLSHandshake, None]:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")

#
# class TLSClientFinish(TLSFinish):
#     """
#     TLS Finish Message
#       when this message will be sent:
#
#         A Finished message is always sent immediately after a change
#         cipher spec message to verify that the key exchange and
#         authentication processes were successful.  It is essential that a
#         change cipher spec message be received between the other handshake
#         messages and the Finished message.
#
#      Meaning of this message:
#
#         The Finished message is the first one protected with the just
#         negotiated algorithms, keys, and secrets.  Recipients of Finished
#         messages MUST verify that the contents are correct.  Once a side
#         has sent its Finished message and received and validated the
#         Finished message from its peer, it may begin to send and receive
#         application data over the connection.
#
#       struct {
#           opaque verify_data[verify_data_length];
#       } Finished;
#
#       verify_data
#          PRF(master_secret, finished_label, Hash(handshake_messages))
#             [0..verify_data_length-1];
#
#       finished_label
#          For Finished messages sent by the client, the string
#          "client finished".  For Finished messages sent by the server,
#          the string "server finished".
#     """
#     from auth.tls_client import TLSClient
#
#     def __init__(self, session: TLSClient):
#         super().__init__(session)
#         raise NotImplementedError("TODO: just a cut&paste stub for now.  nowhere close to what it should be")
#
#     def create(self):
#
#         ]# From older code
#         pre_master_secret, enc_length, encrypted_pre_master_secret = self.cipher_suite.key_exchange.exchange()
#
#         key_exchange_data = constants.PROTOCOL_CLIENT_KEY_EXCHANGE + prepend_length(
#             enc_length + encrypted_pre_master_secret, len_byte_size=3)
#
#         key_exchange_bytes = self.record(constants.CONTENT_TYPE_HANDSHAKE, key_exchange_data)
#         self.messages.append(key_exchange_data)
#
#         change_cipher_spec_bytes = self.record(constants.PROTOCOL_CHANGE_CIPHER_SPEC, b'\x01')
#
#         self.cipher_suite.pre_master_secret = pre_master_secret
#
#         """
#         In SSL/TLS, what is hashed is the handshake messages, i.e. the unencrypted contents. The hash
#         input includes the 4-byte headers for each handshake message (one byte for the message type,
#         three bytes for the message length); however, it does not contain the record headers, or anything
#         related to the record processing (so no padding or MAC). The "ChangeCipherSpec" message (a single
#         byte of value 1) is not a "handshake message" so it is not included in the hash input.
#         """
#         pre_message = b''.join(self.messages)  # Exclude record layer
#
#         verify_data = self.cipher_suite.sign_verify_data(pre_message)
#         verify_bytes = constants.PROTOCOL_CLIENT_FINISH + prepend_length(verify_data, len_byte_size=3)
#
#         kwargs = {
#             'content_bytes': verify_bytes,
#             'seq_num': self.client_sequence_number,
#             'content_type': constants.CONTENT_TYPE_HANDSHAKE
#         }
#         encrypted_finished = self.cipher_suite.encrypt(**kwargs)
#         encrypted_finished_bytes = self.record(constants.CONTENT_TYPE_HANDSHAKE, encrypted_finished)
#         self.messages.append(verify_bytes)
#
#     @staticmethod
#     def parse(frame: bytes) -> Union[TLSHandshake, None]:
#         raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
#
#     def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
#         raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
#
#
# class TLSServerFinish(TLSFinish):
#     """
#     TLS Finish Message
#       when this message will be sent:
#
#         A Finished message is always sent immediately after a change
#         cipher spec message to verify that the key exchange and
#         authentication processes were successful.  It is essential that a
#         change cipher spec message be received between the other handshake
#         messages and the Finished message.
#
#      Meaning of this message:
#
#         The Finished message is the first one protected with the just
#         negotiated algorithms, keys, and secrets.  Recipients of Finished
#         messages MUST verify that the contents are correct.  Once a side
#         has sent its Finished message and received and validated the
#         Finished message from its peer, it may begin to send and receive
#         application data over the connection.
#
#       struct {
#           opaque verify_data[verify_data_length];
#       } Finished;
#
#       verify_data
#          PRF(master_secret, finished_label, Hash(handshake_messages))
#             [0..verify_data_length-1];
#
#       finished_label
#          For Finished messages sent by the client, the string
#          "client finished".  For Finished messages sent by the server,
#          the string "server finished".
#     """
#     from auth.tls_server import TLSServer
#
#     def __init__(self, session: TLSServer):
#         super().__init__(session)
#         raise NotImplementedError("TODO: just a cut&paste stub for now.  nowhere close to what it should be")
#
#     @staticmethod
#     def parse(frame: bytes) -> Union[TLSHandshake, None]:
#         raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
#
#     def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
#         raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")
