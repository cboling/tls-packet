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


    """

    def __init__(self, session):
        super().__init__(TLSHandshakeType.FINISHED)
        self._session = session
        raise NotImplementedError("TODO: just a cut&paste stub for now.  nowhere close to what it should be") \
 \
              @ staticmethod

    def parse(frame: bytes, *args, **kwargs) -> Union[TLSHandshake, None]:
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
