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
from enum import IntEnum
from typing import Union, Optional

from tls_packet.auth.diffle_hellman_public_value import ClientDiffieHellmanPublic
from tls_packet.auth.rsa_premaster_secret import RSAPreMasterSecret
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
from tls_packet.auth.tls_record import TLSRecord
from tls_packet.packet import PARSE_ALL


class TLSClientKeyEncoding(IntEnum):
    """
    Encoding type of client key

        The encoding in the message is implied by the protocol and this is mainly to help
        with debugging and output
    """
    UNKNOWN = 0
    RSA_PREMASTER_SECRET = 1                # RSAPreMasterSecret
    CLIENT_DIFFIE_HELLMAN_PUBLIC = 2        # ClientDiffieHellmanPublic

    def name(self) -> str:
        return super().name.replace("_", " ").capitalize()


class TLSClientKeyExchange(TLSHandshake):
    """
    Client Key Exchange Message

      This message is always sent by the client.  It MUST immediately
      follow the client certificate message, if it is sent.  Otherwise,
      it MUST be the first message sent by the client after it receives
      the ServerHelloDone message.

      With this message, the premaster secret is set, either by direct
      transmission of the RSA-encrypted secret or by the transmission of
      Diffie-Hellman parameters that will allow each side to agree upon
      the same premaster secret.

      When the client is using an ephemeral Diffie-Hellman exponent,
      then this message contains the client's Diffie-Hellman public
      value.  If the client is sending a certificate containing a static
      DH exponent (i.e., it is doing fixed_dh client authentication),
      then this message MUST be sent but MUST be empty.

      The choice of messages depends on which key exchange method has
      been selected.  See Section 7.4.3 for the KeyExchangeAlgorithm
      definition.

          struct {
              select (KeyExchangeAlgorithm) {
                  case rsa:
                      EncryptedPreMasterSecret;
                  case dhe_dss:
                  case dhe_rsa:
                  case dh_dss:
                  case dh_rsa:
                  case dh_anon:
                      ClientDiffieHellmanPublic;
              } exchange_keys;

    """
    def __init__(self, *args,
                 key: Union[RSAPreMasterSecret, ClientDiffieHellmanPublic, None] = None, **kwargs):
        super().__init__(TLSHandshakeType.CLIENT_KEY_EXCHANGE, *args, **kwargs)

        if key is None:
            self.encoding = TLSClientKeyEncoding.UNKNOWN
        elif isinstance(key, RSAPreMasterSecret):
            self.encoding = TLSClientKeyEncoding.RSA_PREMASTER_SECRET
        elif isinstance(key, ClientDiffieHellmanPublic):
            self.encoding = TLSClientKeyEncoding.CLIENT_DIFFIE_HELLMAN_PUBLIC
        else:
            raise ValueError(f'Unknown/Unsupported Client Exchange Key Type: '{type(key)}'")

        self._key = key

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        key_buffer = bytes(self._key)
        key_len = struct.pack("!I", len(key_buffer))  # We only want 24-bits
        buffer = key_len[1:] + key_buffer

        return super().pack(payload=buffer)

    @staticmethod
    def create(server_key_record: Union[TLSRecord, None], server_certificate: Union[TLSRecord, None]) -> 'TLSClientKeyExchange':
        if server_certificate is not None:
            if server_certificate.content_type != TLSHandshakeType.CERTIFICATE:
                raise ValueError(f"TLSClientKeyExchange.create: TLS Certificate Record must be TLSCertificate or None, received '{type(server_certificate)}'")
            certificate = server_key_record.get_layer("TLSCertificate")
            server_public_key = b''
        else:
            server_public_key = b''

        if server_key_record is None:
            pass
            data = b''
            pass
            pass
            key = RSAPreMasterSecret(data, server_public_key)

            return TLSClientKeyExchange(key)

        if server_key_record.content_type != TLSHandshakeType.SERVER_KEY_EXCHANGE:
            raise ValueError(f"TLSClientKeyExchange.create: TLS Server Key Exchange Record must be TLSServerKeyExchange or None, received '{type(server_key_record)}'")

        server_key_exchange = server_key_record.get_layer("TLSServerKeyExchange")
        pass
        pass
        pass
        pass
        pass
        key = ClientDiffieHellmanPublic()
        return TLSClientKeyExchange(key)
