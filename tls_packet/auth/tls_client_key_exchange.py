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
from typing import Union, Optional

from tls_packet.auth.diffle_hellman_public_value import ClientDiffieHellmanPublic
from tls_packet.auth.rsa_premaster_secret import RSAPreMasterSecret
from tls_packet.auth.tls_handshake import TLSHandshake, TLSHandshakeType
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

    @classmethod
    def has_value(cls, val: int) -> bool:
        return val in cls._value2member_map_


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
                 key: Union[RSAPreMasterSecret, ClientDiffieHellmanPublic, bytes] = None, **kwargs):
        super().__init__(TLSHandshakeType.CLIENT_KEY_EXCHANGE, *args, **kwargs)

        if key is None or isinstance(key, bytes):
            self._encoding = TLSClientKeyEncoding.UNKNOWN
        elif isinstance(key, RSAPreMasterSecret):
            self._encoding = TLSClientKeyEncoding.RSA_PREMASTER_SECRET
        elif isinstance(key, ClientDiffieHellmanPublic):
            self._encoding = TLSClientKeyEncoding.CLIENT_DIFFIE_HELLMAN_PUBLIC
        else:
            raise ValueError(f"Unknown/Unsupported Client Exchange Key Type: '{type(key)}'")

        self._key = key

    @property
    def encoding(self) -> TLSClientKeyEncoding:
        return self._encoding

    @property
    def key(self) -> Union[RSAPreMasterSecret, ClientDiffieHellmanPublic]:
        return self._key

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        raise NotImplementedError("TODO: Not yet implemented since we are functioning as a client")

    def pack(self, payload: Optional[Union[bytes, None]] = None) -> bytes:
        key_buffer = bytes(self._key)
        return super().pack(payload=key_buffer)

    @staticmethod
    def create(session: 'TLSClient') -> 'TLSClientKeyExchange':
        """
        For all key exchange methods, the same algorithm is used to convert
        the pre_master_secret into the master_secret.  The pre_master_secret
        should be deleted from memory once the master_secret has been
        computed.

          master_secret = PRF(pre_master_secret, "master secret",
                              ClientHello.random + ServerHello.random)
                              [0..47];

        The master secret is always exactly 48 bytes in length.  The length
        of the premaster secret will vary depending on key exchange method.

        RSA

           When RSA is used for server authentication and key exchange, a 48-
           byte pre_master_secret is generated by the client, encrypted under
           the server's public key, and sent to the server.  The server uses its
           private key to decrypt the pre_master_secret.  Both parties then
           convert the pre_master_secret into the master_secret, as specified
           above.

        Diffie-Hellman

           A conventional Diffie-Hellman computation is performed.  The
           negotiated key (Z) is used as the pre_master_secret, and is converted
           into the master_secret, as specified above.  Leading bytes of Z that
           contain all zero bits are stripped before it is used as the
           pre_master_secret.

           Note: Diffie-Hellman parameters are specified by the server and may
           be either ephemeral or contained within the server's certificate.
        """
        from cryptography.hazmat.primitives import serialization

        from tls_packet.auth.tls_client_key_exchange import TLSClientKeyExchange
        # Look up what the server sent us
        server_certificate= next((record.get_layer("TLSCertificate") for record in session.received_handshake_records
                                  if record.has_layer("TLSCertificate")), None)
        server_key_exchange = next((record.get_layer("TLSServerKeyExchange") for record in session.received_handshake_records
                                    if record.has_layer("TLSServerKeyExchange")), None)

        client_public_key = session.public_key
        client_private_key = session.private_key

        # Convert server certificate into a serializer/encrypter...
        if server_certificate is not None:
            server_public_key = serialization.load_der_public_key(server_certificate)
        else:
            server_public_key = None

        if server_key_exchange is None:
            raise NotImplementedError("RSA Premaster Secret is not supported")
            # key = RSAPreMasterSecret(data, server_public_key)
            # return TLSClientKeyExchange(key)

        pass
        pass
        pass
        pass
        pass
        key = ClientDiffieHellmanPublic()
        return TLSClientKeyExchange(key)
