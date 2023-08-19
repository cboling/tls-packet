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
# pylint: skip-file

import struct

from tls_packet.eap import EapCode, EapIdentity, EapMd5Challenge
from tls_packet.eapol import EapolType, Eapol

FIXED_RANDOM = b"".join(struct.pack('B', index) for index in range(32))


class MockPacket:
    def __init__(self, message_id=0, identity='bruno', challenge=b"md5CHALL", secret="ourlittlesecret"):
        self.message_id = message_id
        self.identity = identity
        self.challenge = challenge
        self.secret = secret

    def create_packet(self, packet_type, valid, packet_id=None):
        if packet_id:
            self.message_id = packet_id

        if packet_type == PacketType.EAPOL_START:
            if valid:
                return Eapol(1, EapolType.EAPOL_START.value, b"")
            return Eapol(1, 999, b"")

        elif packet_type == PacketType.EAP_IDENT_RESPONSE:
            if valid:
                return EapIdentity(EapCode.RESPONSE.value, self.message_id, self.identity)
            return EapIdentity(EapCode.RESPONSE.value, 999, self.identity)

        elif packet_type == PacketType.EAP_AUTH_RESPONSE:
            if valid:
                return EapMd5Challenge(EapCode.RESPONSE.value, self.message_id, self.challenge)
            return EapMd5Challenge(EapCode.RESPONSE.value, 999, self.challenge)
