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
from tls_packet.packet import PARSE_ALL


class TLSHelloRequest(TLSHandshake):
    """
        When this message will be sent:

          The HelloRequest message MAY be sent by the server at any time.

        Meaning of this message:

          HelloRequest is a simple notification that the client should begin
          the negotiation process anew.  In response, the client should send
          a ClientHello message when convenient.  This message is not
          intended to establish which side is the client or server but
          merely to initiate a new negotiation.  Servers SHOULD NOT send a
          HelloRequest immediately upon the client's initial connection.  It
          is the client's job to send a ClientHello at that time.

          This message will be ignored by the client if the client is
          currently negotiating a session.  This message MAY be ignored by
          the client if it does not wish to renegotiate a session, or the
          client may, if it wishes, respond with a no_renegotiation alert.
          Since handshake messages are intended to have transmission
          precedence over application data, it is expected that the
          negotiation will begin before no more than a few records are
          received from the client.  If the server sends a HelloRequest but
          does not receive a ClientHello in response, it may close the
          connection with a fatal alert.

          After sending a HelloRequest, servers SHOULD NOT repeat the
          request until the subsequent handshake negotiation is complete.

        Structure of this message:

          struct { } HelloRequest;

        This message MUST NOT be included in the message hashes that are
        maintained throughout the handshake and used in the Finished messages
        and the certificate verify message.
    """

    def __init__(self, **kwargs):
        super().__init__(TLSHandshakeType.HELLO_REQUEST, length=0, session=None, **kwargs)

    @staticmethod
    def parse(frame: bytes, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union[TLSHandshake, None]:
        return TLSHelloRequest(original_frame=frame, **kwargs)
