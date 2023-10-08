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

import logging
import os
import sys
from datetime import datetime
from typing import Tuple, Optional, List, Iterable, Dict, Any, Union

from tls_packet.auth.cipher_suites import CipherSuite
from tls_packet.auth.security_params import SecurityParameters
from tls_packet.auth.security_params import TLSKeyExchangeTypes
from tls_packet.auth.tls import TLS, TLSv1, TLSv1_2
from tls_packet.auth.tls_extension import TLSHelloExtension
from tls_packet.auth.tls_state_machine import TLSClientStateMachine
from tls_packet.packet import Packet

logger = logging.getLogger(__name__)


class TLSClient:
    """ TLS Client """

    def __init__(self, auth_socket,
                 tls_version: Optional[TLS] = None,
                 session_id: Optional[int] = 0,
                 ciphers: Optional[dict] = None,
                 random_data: Optional[bytes] = None,
                 extensions: Optional[Iterable[TLSHelloExtension]] = None,
                 certificates: Optional[Dict[str, Any]] = None,
                 keys: Optional[Dict[str, Any]] = None,
                 debug: Optional[bool] = False):

        self.auth_socket = auth_socket

        self._tls_version = tls_version or TLSv1_2()
        self._supported_tls_versions = (TLSv1(), TLSv1_2())

        # TODO: See what we can get rid of...
        # TODO: Move read-only attributes to protected names and provide @property access
        self.client_sequence_number = 0
        self.server_sequence_number = 0

        # Client random data is 32 bytes long
        client_random = random_data or int(datetime.now().timestamp()).to_bytes(4, 'big') + os.urandom(28)

        # Keep separate send/receive parameters so we can handle various receive sequences from server

        # self._receive_security_parameters: SecurityParameters = SecurityParameters().copy(client_random=client_random)
        # self._send_security_parameters: SecurityParameters = SecurityParameters().copy(client_random=client_random)

        # TLS breaks it up into pending and active  (Look at state machine and its transitions setting of this)
        # it uses the following, so tie the values below into what we save here
        #         self._k_send = ""
        #         self._k_recv = ""
        #
        self._security_parameters = {
            'active_tx':  SecurityParameters().copy(tls_version=self._tls_version, client_random=client_random),
            'active_rx':  SecurityParameters().copy(tls_version=self._tls_version, client_random=client_random),
            'pending_tx': SecurityParameters().copy(tls_version=self._tls_version, client_random=client_random),
            'pending_rx': SecurityParameters().copy(tls_version=self._tls_version, client_random=client_random)
        }
        #  So when we get the server_hello, use the 'pending_send_parameters' to stuff values in and later on during
        #  server_key_exchange download, use that pending value
        #
        # static void init_protection_parameters( ProtectionParameters *parameters )
        # {
        #   parameters->MAC_secret = NULL;
        #   parameters->key = NULL;
        #   parameters->IV = NULL;
        #   parameters->seq_num = 0;
        #   parameters->suite = TLS_NULL_WITH_NULL_NULL;
        # }

        # self.server_random = None
        self.session_id = session_id
        # TODO: PSK not yet supported
        excluded = (TLSKeyExchangeTypes.RSA_PSK, TLSKeyExchangeTypes.DHE_PSK, TLSKeyExchangeTypes.ECDHE_PSK)
        self.ciphers = ciphers or CipherSuite.get_cipher_suites_by_version(self.tls_version, excluded=excluded)
        self.extensions = extensions

        # Following are decode from server messages.  Any better place for them
        self.server_certificates = None
        self.server_public_key = b""

        # TODO: Next are copied over from the AUTH machine and may or may not be used
        #       so we need to investigate if they are used or are duplicated above

        certificates = certificates or {}
        keys = keys or {}
        self.certificate = certificates.get("certificate")
        self.ca_certificate = certificates.get("ca_certificate")
        self.public_key = keys.get("public")
        self.private_key = keys.get("private")

        self.tls_session = None

        print("*** Not enforcing client EAP-TLS fragmentation yet")
        self.eap_tls_client_data_max_len = 16000

        self._debug = debug

        # Probably want these - TODO Eventually calculate the hash on the fly if possible
        self._client_handshake_records_sent: List['TLSRecord'] = []
        self._server_handshake_records_received: List['TLSRecord'] = []

        # From earlier work     TODO: Remove old code

        self.eap_tls_server_data = b''
        self.eap_tls_expected_len = 0
        self.eap_tls_last_id = 256
        self.tls_session = None
        self.eap_tls_client_data_len = 0
        self.eap_tls_client_data_max_len = 994

        self._eap_tls_last_sent_id = 256
        self._eap_tls_last_sent_data = None

        # TODO: Deprecate much above and move to this
        self.state_machine: TLSClientStateMachine = TLSClientStateMachine(self)

    def rx_security_parameters(self, active: Optional[bool] = True) -> SecurityParameters:
        return self._security_parameters["active_rx" if active else "pending_rx"]

    def tx_security_parameters(self, active: Optional[bool] = True) -> SecurityParameters:
        return self._security_parameters["active_tx" if active else "pending_tx"]

    @property
    def tls_version(self) -> TLS:
        return self._tls_version

    def set_tls_version(self, version: TLS) -> bool:
        """ Call this routine with the version that the server requests in the Server Hello """
        if version not in self._supported_tls_versions:
            # TODO: Do we send an alert?
            print(f"Server TLS Version {version} is not supported. We only support: {', '.join(ver for ver in self._supported_tls_versions)}",
                  file=sys.stderr)
            return False

        # Set it across the board in all locations. We must use what server suggests if we can
        self._tls_version = version
        for key in ('active_tx', 'active_rx', 'pending_tx', 'pending_rx'):
            self._security_parameters[key].tls_version = version

        return True

    @property
    def received_handshake_records(self) -> Tuple['TLSHandshakeRecord']:
        return tuple(self._server_handshake_records_received)

    def debug_print(self, title, message, *, prefix=''):
        if self._debug:
            logging.info(prefix, title, message)

    def log_error(self, success: bool, msg: str) -> None:
        if not success:
            logging.error(msg)
            raise RuntimeError(msg)

    def close(self) -> None:
        sm, self.state_machine = self.state_machine, None
        if sm is not None:
            sm.close()

        self.auth_socket = None

    def read(self, frame: bytes) -> Tuple[bytes, bytes, bytes]:
        record_layer, frame = frame[:5], frame[5:]

        read_bytes = required_bytes = int.from_bytes(record_layer[3:5], 'big')
        per_recv = 1000
        data = b''

        # TODO: This use to receive data from a socket, improve it for frame buffer reading
        while read_bytes > 0:
            read_size = min(per_recv, read_bytes)
            data += frame[:read_size]
            frame = frame[read_size:]
            read_bytes = required_bytes - len(data)

        self.log_error(len(data) == required_bytes, f'Wrong size: expected {required_bytes}, got {len(data)}')
        return record_layer, data, frame

    # TODO:  Currently working on TLSClient to create a CLientHello insicde a TLSHandshake record.

    def handle_tls_data(self, eap_id: int, eap_tls: 'EAP_TLS', eap: 'EAP') -> None:
        # TODO: If our 'Last EAP ID' and 'This EAP ID' IDENTS always match, we may be able to get rid
        #       of EAP ID knowledge in the TLSClientStateMachine
        print(f"*** Last EAP ID: {eap_id}, EAP-LAST-ID: {self.eap_tls_last_id}")

        if self.state_machine.state == TLSClientStateMachine.INITIAL:
            print(f"TLSClient.handle_tls_data: Start: {eap_id}")
            self.state_machine.start(eap_id=eap_id)

        elif eap_id == self._eap_tls_last_sent_id and self._eap_tls_last_sent_data is not None:
            # Handle a retransmit
            print(f"TLSClient.handle_tls_data: Rx retransmit: eap_id: {eap_id}")
            self.auth_socket.send_response(eap_id, self._eap_tls_last_sent_data)

        else:
            """
            Handle new server data

              After we send the ClientHello, the EAP server will then respond with an
              EAP-Request packet with EAP-Type=EAP-TLS. The data field of this packet will
              encapsulate one or more TLS records.

              These will contain a TLS server_hello handshake message, possibly followed by
              TLS certificate, server_key_exchange, certificate_request, server_hello_done
              and/or finished handshake messages, and/or a TLS change_cipher_spec message.

              The server_hello handshake message contains a TLS version number, another random
              number, a sessionId, and a cipher suite.  The version offered by the server MUST
              correspond to TLS v1.0 or later.
            """
            # Decode packet
            packets = self._rx_server_eap_tls(eap_id, eap_tls)

            if packets is None:
                # Send the response (ACK the fragment). Do not send if EAP Failure
                self.auth_socket.send_response(eap_id, b'')
                return

            # Save single records into a list so we can easily do a for-loop
            if isinstance(packets, Packet):
                packets = [packets]

            # Feed the records into the TLS Client State machine
            for packet in packets:
                # TOD0: Drop eap_id if we can get away with it
                self.save_server_record(packet)
                self.state_machine.rx_packet(eap_id, packet)

    def _rx_server_eap_tls(self, eap_id: int, eap_tls: Union['EAP_TLS', 'EapTls']) -> Union[Packet, List[Packet], None]:
        """
        Handle server data

          After we send the ClientHello, the EAP server will then respond with an
          EAP-Request packet with EAP-Type=EAP-TLS. The data field of this packet will
          encapsulate one or more TLS records.

          These will contain a TLS server_hello handshake message, possibly followed by
          TLS certificate, server_key_exchange, certificate_request, server_hello_done
          and/or finished handshake messages, and/or a TLS change_cipher_spec message.

          The server_hello handshake message contains a TLS version number, another random
          number, a sessionId, and a ciphersuite.  The version offered by the server MUST
          correspond to TLS v1.0 or later.
        """
        print(f"EAP-TLS: Rx Message: ID: {eap_id}, S: {eap_tls.S}, M: {eap_tls.M}, L: {eap_tls.L}")

        if self.eap_tls_expected_len == 0:
            # We expect this to be the  EAP-TLS Request after we sent the client hello
            expected_id = self.eap_tls_last_id = eap_id

            if eap_tls.L:
                self.eap_tls_expected_len = eap_tls.tls_message_len  # Has length
        else:
            expected_id = self.eap_tls_last_id + 1 if self.eap_tls_last_id < 255 else 0

        # Sanity check
        if eap_tls.L and self.eap_tls_expected_len != eap_tls.tls_message_len:
            print(f"**** EAP-TLS frame size changed from {self.eap_tls_expected_len} to {eap_tls.tls_message_len}")
            # TODO: Send Alert?

        # Watch for retransmissions
        if eap_id == expected_id:
            self.eap_tls_last_id = eap_id

            tls_data = eap_tls.tls_data if hasattr(eap_tls, "tls_data") else eap_tls.data
            self.eap_tls_server_data += tls_data

            # Sanity check
            if len(self.eap_tls_server_data) > self.eap_tls_expected_len:
                print(f"Server data length exceeded {len(self.eap_tls_server_data)} > {self.eap_tls_expected_len}")
                # logger.error(f"CPE: {cpe_mac_addr}: Server data length exceeded {len(eap_tls_server_data)} > {self.eap_tls_expected_len}")
                # TODO: Do something else here, log it, ...
                # TODO: Send Alert?

            # Done?
            more_expected = eap_tls.M

            if more_expected == 0:
                # Extract records from the server handshake
                print(f"All fragments received {len(self.eap_tls_server_data)}/{self.eap_tls_expected_len}")
                from tls_packet.auth.tls_record import TLSRecord

                try:
                    print(f"Reassembled packet: {self.eap_tls_server_data.hex()}")
                    record_list = TLSRecord.parse(self.eap_tls_server_data, security_params=self.rx_security_parameters())

                except Exception as _e:
                    record_list = None
                    raise _e

                return record_list
        else:
            print(f"EAP Possible duplicate (ID != expected): {eap_id} != {expected_id}")

    def send_response(self, eap_id: int, data: bytes, **kwargs):
        print(f"*** This EAP ID: {eap_id}, EAP-LAST-ID: {self.eap_tls_last_id}")
        self._eap_tls_last_sent_id = eap_id
        self._eap_tls_last_sent_data = data
        self.auth_socket.send_response(eap_id, data, **kwargs)

    def save_client_record(self, record: Union["TLSRecord", List["TLSRecord"]]) -> None:
        """ Save off client records so that TLSFinish can be correctly created """
        from tls_packet.auth.tls_record import TLSRecord

        if isinstance(record, TLSRecord):
            self._client_handshake_records_sent.append(record)

        elif isinstance(record, list):
            for rec in record:
                self.save_client_record(rec)
        else:
            raise ValueError(f"TLSClientStateMachine: Save client records expected a TLSRecord or list of TLSRecord. Got: type{record}")

    def save_server_record(self, record: Union["TLSRecord", List["TLSRecord"]]) -> None:
        """ Save off server records so that TLSFinish can be correctly created """
        from tls_packet.auth.tls_record import TLSRecord

        if isinstance(record, TLSRecord):
            self._server_handshake_records_received.append(record)

        elif isinstance(record, list):
            for rec in record:
                self.save_server_record(rec)
        else:
            raise ValueError(f"TLSClientStateMachine: Save server records expected a TLSRecord or list of TLSRecord. Got: type{record}")

    # message = self.record(constants.CONTENT_TYPE_HANDSHAKE, client_hello_bytes, tls_version=tls.TLSV1())
    # self.conn.send(message)
    # self.messages.append(client_hello_bytes)
    def client_hello(self) -> 'TLSClientHello':
        from tls_packet.auth.tls_client_hello import TLSClientHello
        return TLSClientHello(self)

    def create_tls_handshake_record(self, message: 'TLSHandshake') -> 'TLSHandshakeRecord':
        # Create the record
        from tls_packet.auth.tls_record import TLSHandshakeRecord

        record = TLSHandshakeRecord(message, session=self)
        # Save it off so we can compute our Finish message when needed
        self.save_client_record(record)
        return record

    # def client_finish(self):
    #     pre_master_secret, enc_length, encrypted_pre_master_secret = self.cipher_suite.key_exchange.exchange()
    #
    #     key_exchange_data = PROTOCOL_CLIENT_KEY_EXCHANGE + prepend_length(
    #         enc_length + encrypted_pre_master_secret, len_byte_size=3)
    #
    #     key_exchange_bytes = self.record(CONTENT_TYPE_HANDSHAKE, key_exchange_data)
    #     self.messages.append(key_exchange_data)
    #
    #     change_cipher_spec_bytes = self.record(PROTOCOL_CHANGE_CIPHER_SPEC, b'\x01')
    #
    #     self.cipher_suite.pre_master_secret = pre_master_secret
    #
    #     # TODO: below is old stuff we needed for scapy that never worked
    #     # record_types = (self._eap_tls_generate_client_certificate,
    #     #                 self._eap_tls_generate_client_key_exchange,
    #     #                 self._eap_tls_generate_certificate_verify,
    #     #                 self._eap_tls_generate_change_cipher_spec,
    #     #                 self._eap_tls_generate_encrypted_handshake_message)
    #     """
    #     In SSL/TLS, what is hashed is the handshake messages, i.e. the unencrypted contents. The hash
    #     input includes the 4-byte headers for each handshake message (one byte for the message type,
    #     three bytes for the message length); however, it does not contain the record headers, or anything
    #     related to the record processing (so no padding or MAC). The "ChangeCipherSpec" message (a single
    #     byte of value 1) is not a "handshake message" so it is not included in the hash input.
    #     """
    #     pre_message = b''.join(self.messages)  # Exclude record layer
    #
    #     verify_data = self.cipher_suite.sign_verify_data(pre_message)
    #     verify_bytes = PROTOCOL_CLIENT_FINISH + prepend_length(verify_data, len_byte_size=3)
    #
    #     kwargs = {
    #         'content_bytes': verify_bytes,
    #         'seq_num': self.client_sequence_number,
    #         'content_type': CONTENT_TYPE_HANDSHAKE
    #     }
    #     encrypted_finished = self.cipher_suite.encrypt(**kwargs)
    #     encrypted_finished_bytes = self.record(CONTENT_TYPE_HANDSHAKE, encrypted_finished)
    #     self.messages.append(verify_bytes)
    #
    #     self.client_sequence_number += 1
    #
    #     message = key_exchange_bytes + change_cipher_spec_bytes + encrypted_finished_bytes
    #
    #     if self.is_server_key_exchange:
    #         self._debug_print(f'Key Exchange Client Public Key ({len(encrypted_pre_master_secret)!s} bytes)',
    #                          print_hex(encrypted_pre_master_secret))
    #     else:
    #         self._debug_print('Encrypted pre master secret', print_hex(encrypted_pre_master_secret))
    #
    #     self._debug_print('Pre master secret', print_hex(pre_master_secret))
    #     self._debug_print('Master secret', print_hex(self.cipher_suite.keys['master_secret']))
    #     self._debug_print('Verify data', print_hex(verify_data))
    #
    #     return message
    #
    # def server_finish(self, frame: bytes) -> bool:
    #     while True:
    #         record, content, frame = self.read(frame)
    #         if record[:1] == CONTENT_TYPE_ALERT:
    #             if content == ERROR_FATAL + ERROR_CODE_BAD_RECORD_MAC:
    #                 raise Exception('Bad record mac')
    #             raise Exception(print_hex(content))
    #
    #         if content[:1] == PROTOCOL_NEW_SESSION_TICKET:
    #             self.messages.append(content)
    #             # @todo save session ticket
    #             pass
    #
    #         elif record[:1] == PROTOCOL_SERVER_FINISH:
    #             pass
    #
    #         elif record[:1] == CONTENT_TYPE_HANDSHAKE:
    #             kwargs = {
    #                 'encrypted_bytes': content,
    #                 'seq_num': self.server_sequence_number,
    #                 'content_type': CONTENT_TYPE_HANDSHAKE
    #             }
    #
    #             content = self.cipher_suite.decrypt(**kwargs)
    #             if content[:1] != PROTOCOL_SERVER_FINISH:
    #                 logging.error(ValueError('Not server finished'))
    #                 return False
    #
    #             pre_message = b''.join(self.messages)  # Exclude record layer
    #             verify_data = content[4:]
    #             self.cipher_suite.verify_verify_data(pre_message, verify_data)
    #             self.server_sequence_number += 1
    #             break
    #
    #     self._debug_print('Verify data', print_hex(verify_data))
    #     return True

    def client_finish(self) -> 'TLSClientFinish':

        raise NotADirectoryError("TODO")
        #
        # pre_master_secret, enc_length, encrypted_pre_master_secret = self.cipher_suite.key_exchange.exchange()
        #
        # key_exchange_data = constants.PROTOCOL_CLIENT_KEY_EXCHANGE + prepend_length(
        #     enc_length + encrypted_pre_master_secret, len_byte_size=3)
        #
        # key_exchange_bytes = self.record(constants.CONTENT_TYPE_HANDSHAKE, key_exchange_data)
        # self.messages.append(key_exchange_data)
        #
        # change_cipher_spec_bytes = self.record(constants.PROTOCOL_CHANGE_CIPHER_SPEC, b'\x01')
        #
        # self.cipher_suite.pre_master_secret = pre_master_secret
        #
        # """
        # In SSL/TLS, what is hashed is the handshake messages, i.e. the unencrypted contents. The hash
        # input includes the 4-byte headers for each handshake message (one byte for the message type,
        # three bytes for the message length); however, it does not contain the record headers, or anything
        # related to the record processing (so no padding or MAC). The "ChangeCipherSpec" message (a single
        # byte of value 1) is not a "handshake message" so it is not included in the hash input.
        # """
        # pre_message = b''.join(self.messages)  # Exclude record layer
        #
        # verify_data = self.cipher_suite.sign_verify_data(pre_message)
        # verify_bytes = constants.PROTOCOL_CLIENT_FINISH + prepend_length(verify_data, len_byte_size=3)
        #
        # kwargs = {
        #     'content_bytes': verify_bytes,
        #     'seq_num':       self.client_sequence_number,
        #     'content_type':  constants.CONTENT_TYPE_HANDSHAKE
        # }
        # encrypted_finished = self.cipher_suite.encrypt(**kwargs)
        # encrypted_finished_bytes = self.record(constants.CONTENT_TYPE_HANDSHAKE, encrypted_finished)
        # self.messages.append(verify_bytes)
        #
        # self.client_sequence_number += 1
        # self.conn.send(key_exchange_bytes + change_cipher_spec_bytes + encrypted_finished_bytes)
        # if self.is_server_key_exchange:
        #     self.debug_print('Key Exchange Client Public Key ({!s} bytes)'.format(len(encrypted_pre_master_secret)),
        #                      print_hex(encrypted_pre_master_secret))
        # else:
        #     self.debug_print('Encrypted pre master secret', print_hex(encrypted_pre_master_secret))
        # self.debug_print('Pre master secret', print_hex(pre_master_secret))
        # self.debug_print('Master secret', print_hex(self.cipher_suite.keys['master_secret']))
        # self.debug_print('Verify data', print_hex(verify_data))
        #
        # if self.ssl_key_logfile:
        #     with open(self.ssl_key_logfile, 'a') as f:
        #         f.write(f'CLIENT_RANDOM {self.client_random.hex()} {self.cipher_suite.keys["master_secret"].hex()}\n')

    def sever_finish(self, msg: 'TLSServerFinish') -> None:

        raise NotADirectoryError("TODO")
        #
        #     while True:
        #         record, content = self.read(return_record=True)
        #         if record[:1] == constants.CONTENT_TYPE_ALERT:
        #             if content == constants.ERROR_FATAL + constants.ERROR_CODE_BAD_RECORD_MAC:
        #                 raise Exception('Bad record mac')
        #             raise Exception(print_hex(content))
        #         if content[:1] == constants.PROTOCOL_NEW_SESSION_TICKET:
        #             self.messages.append(content)
        #             # @todo save session ticket
        #             pass
        #         elif record[:1] == constants.PROTOCOL_SERVER_FINISH:
        #             pass
        #         elif record[:1] == constants.CONTENT_TYPE_HANDSHAKE:
        #             kwargs = {
        #                 'encrypted_bytes': content,
        #                 'seq_num': self.server_sequence_number,
        #                 'content_type': constants.CONTENT_TYPE_HANDSHAKE
        #             }
        #
        #             content = self.cipher_suite.decrypt(**kwargs)
        #             assert content[:1] == constants.PROTOCOL_SERVER_FINISH, ValueError('Not server finished')
        #
        #             pre_message = b''.join(self.messages)  # Exclude record layer
        #             verify_data = content[4:]
        #             self.cipher_suite.verify_verify_data(pre_message, verify_data)
        #             self.server_sequence_number += 1
        #             break
        #     self.debug_print('Verify data', print_hex(verify_data))
