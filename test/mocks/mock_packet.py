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

from tls_packet.auth.eap import EapResponse, EapCode, EapType, EapIdentity, EapMd5Challenge
from tls_packet.auth.eapol import EAPOLPacketType, EapolStart, EapolLogoff, EapolEAP

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

        if packet_type == EAPOLPacketType.EAPOL_START:
            if valid:
                return EapolStart()
            return EapolStart(version=99)

        elif packet_type == EAPOLPacketType.EAPOL_LOGOFF:
            if valid:
                return EapolLogoff()
            return EapolLogoff(version=99)

        elif packet_type == EapType.EAP_IDENTITY:
            identity = EapIdentity(self.identity)

            if valid:
                auth_response = EapResponse(identity, eap_id=self.message_id)
            else:
                auth_response = EapResponse(identity, eap_id=999)

            # TODO: Next breaks the packet layering. Find way to do add layer
            packet = EapolEAP(eap=auth_response)
            return packet

        elif packet_type == EapType.EAP_MD5_CHALLENGE:
            challenge = EapMd5Challenge(self.message_id, self.challenge)

            if valid:
                auth_response = EapResponse(challenge, eap_id=self.message_id)
            else:
                auth_response = EapResponse(challenge, eap_id=999)

            # TODO: Next breaks the packet layering. Find way to do add layer
            packet = EapolEAP(eap=auth_response)
            return packet
