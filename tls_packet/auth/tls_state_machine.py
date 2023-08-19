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

from typing import Optional, Tuple, List

from tls_packet.auth.security_params import SecurityParameters
from transitions import Machine, State
from transitions.extensions import GraphMachine


class TLSClientStateMachine(Machine):
    """
    TLS Client State Machine: From RFC-8446: Appendix A.1. "

       This appendix provides a summary of the legal state transitions for
       the client and server handshakes.  State names (in all capitals,
       e.g., START) have no formal meaning but are provided for ease of
       comprehension.  Actions which are taken only in certain circumstances
       are indicated in [].  The notation "K_{send,recv} = foo" means "set
       the send/recv key to the given key".

            A.1.  Client
                                          START <----+
                           Send ClientHello |        | Recv HelloRetryRequest
                      [K_send = early data] |        |
                                            v        |
                       /                 WAIT_SH ----+
                       |                    | Recv ServerHello
                       |                    | K_recv = handshake
                   Can |                    V
                  send |                 WAIT_EE
                 early |                    | Recv EncryptedExtensions
                  data |           +--------+--------+
                       |     Using |                 | Using certificate
                       |       PSK |                 v
                       |           |            WAIT_CERT_CR
                       |           |        Recv |       | Recv CertificateRequest
                       |           | Certificate |       v
                       |           |             |    WAIT_CERT
                       |           |             |       | Recv Certificate
                       |           |             v       v
                       |           |              WAIT_CV
                       |           |                 | Recv CertificateVerify
                       |           +> WAIT_FINISHED <+
                       |                  | Recv Finished
                       \                  | [Send EndOfEarlyData]
                                          | K_send = handshake
                                          | [Send Certificate [+ CertificateVerify]]
                Can send                  | Send Finished
                app data   -->            | K_send = K_recv = application
                after here                v
                                      CONNECTED

       Note that with the transitions as shown above, clients may send
       alerts that derive from post-ServerHello messages in the clear or
       with the early data keys.  If clients need to send such alerts, they
       SHOULD first rekey to the handshake keys if possible.
    """

    INITIAL = "initial"
    START = "START"
    WAIT_SH = "WAIT_SH"
    WAIT_EE = "WAIT_EE"
    WAIT_CERT_CR = "WAIT_CERT_CR"
    WAIT_CERT = "WAIT_CERT"
    WAIT_CV = "WAIT_CV"
    WAIT_FINISHED = "WAIT_FINISHED"
    CONNECTED = "CONNECTED"
    CLOSE = "CLOSE"

    STATES = [
        State(START, on_enter="on_enter_tls_start", on_exit="on_exit_tls_start"),
        State(WAIT_SH, on_enter="on_enter_wait_server_hello", on_exit="on_exit_wait_server_hello"),
        State(WAIT_EE, on_enter="on_enter_wait_encrypted_extensions"),
        State(WAIT_CERT_CR, on_enter="on_enter_wait_certificate_request"),
        State(WAIT_CERT, on_enter="on_enter_wait_certificate"),
        State(WAIT_CV, on_enter="on_enter_certificate_verify"),
        State(WAIT_FINISHED, on_enter="on_enter_wait_finished", on_exit="on_exit_wait_finished"),
        State(CONNECTED, on_enter="on_enter_connected"),
        State(CLOSE, on_enter="on_enter_close"),
    ]
    TRANSITIONS = [
        {"trigger": "start", "source": "initial", "dest": START},
        {"trigger": "sent_client_hello", "source": START, "dest": WAIT_SH},

        {"trigger": "rx_hello_retry_request", "source": WAIT_SH, "dest": START},
        {"trigger": "rx_server_hello", "source": WAIT_SH, "dest": WAIT_EE},

        {"trigger": "encrypted_extensions", "source": WAIT_EE, "dest": WAIT_FINISHED, "conditions": "using_psk"},
        {"trigger": "encrypted_extensions", "source": WAIT_EE, "dest": WAIT_CERT_CR, "conditions": "using_certificate"},

        {"trigger": "rx_certificate_request", "source": WAIT_CERT_CR, "dest": WAIT_CERT},
        {"trigger": "rx_certificate", "source": WAIT_CERT_CR, "dest": WAIT_CV},

        {"trigger": "rx_certificate", "source": WAIT_CERT, "dest": WAIT_CV},

        {"trigger": "certificate_verified", "source": WAIT_CV, "dest": WAIT_FINISHED},
        {"trigger": "rx_certificate_request", "source": WAIT_CV, "dest": "="},

        {"trigger": "rx_finished", "source": WAIT_FINISHED, "dest": CONNECTED},
        {"trigger": "rx_certificate_request", "source": WAIT_FINISHED, "dest": "=", "conditions": "using_certificate"},

        # Shutdown from any state shuts machine down
        {"trigger": "rx_alert", "source": "*", "dest": CLOSE, "unless": "inactive"},
    ]

    def __init__(self, session: 'TLSClient'):
        super().__init__(model=self, states=self.STATES, transitions=self.TRANSITIONS,
                         queued=True, initial=self.INITIAL, ignore_invalid_triggers=False)
        self._session = session
        self._closed = False
        self._k_send = ""  # Make IntEnum
        self._k_recv = ""  # Make IntEnum

    def rx_packet(self, eap_id: int, packet: 'Packet'):
        from tls_packet.auth.tls_record import TLSRecord

        if isinstance(packet, TLSRecord):
            if packet.has_layer("TLSHelloRetryRequest"):  # TODO: Not yet supported....
                print("Rx TLSHelloRetryRequest")
                self.rx_hello_retry_request(eap_id=eap_id, frame=packet.get_layer("TLSHelloRetryRequest"))

            elif packet.has_layer("TLSServerHello"):
                print("Rx TLSServerHello")
                self.rx_server_hello(eap_id=eap_id, frame=packet.get_layer("TLSServerHello"))

            elif packet.has_layer("TLSCertificate"):
                print("Rx TLSCertificate")
                self.rx_certificate(eap_id=eap_id, frame=packet.get_layer("TLSCertificate"))

            elif packet.has_layer("TLSCertificateRequest"):
                print("Rx TLSCertificateRequest")
                self.rx_certificate_request(eap_id=eap_id, frame=packet.get_layer("TLSCertificateRequest"))

            elif packet.has_layer("TLSServerHelloDone"):
                print("Rx TLSServerHelloDone")
                self.rx_server_hello_done(eap_id=eap_id)

            elif packet.has_layer("TLSFinish"):
                print("Rx TLSFinish")
                self.rx_finished(eap_id=eap_id, frame=packet.get_layer("TLSFinish"))

            elif any(packet.has_layer(layer) for layer in ("TLSServerKeyExchange",)):
                print(f"Rx {packet}: No special trigger attached")

            else:
                raise ValueError(f"TLSClientStateMachine: {self.state}: Unsupported TLSRecord Type: {packet}")

        else:
            raise ValueError(f"TLSClientStateMachine: {self.state}: Unsupported Packet Type: {packet}")

    @property
    def session(self) -> 'TLSClient':
        return self._session

    @property
    def security_parameters(self) -> SecurityParameters:
        return self._session.security_parameters

    def using_psk(self, *args, **kwargs) -> bool:
        print(f"TLSClientStateMachine: 'using_psk' condition is currently hardcoded to 'False'")
        return False

    def using_certificate(self, *args, **kwargs) -> bool:
        print(f"TLSClientStateMachine: 'using_certificates' condition is currently hardcoded to 'True'")
        return True

    def on_enter_tls_start(self, *args, eap_id: Optional[int] = 256, **kwargs):
        """
            {"trigger": "start", "source": START, "dest": "="},
        """
        print(f"{self.state}: entry")
        self._k_send = ""
        self._k_recv = ""

        # Construct and send Client Hello
        from tls_packet.auth.tls_client_hello import TLSClientHello
        client_hello = TLSClientHello(self)

        # Wrap it in a record, save it off for the Client Finish
        client_hello_record = self._session.create_tls_handshake_record(client_hello)

        print(f"Client Hello Record: {client_hello_record}")
        print(f"Hello Data: {bytes(client_hello_record).hex()}")

        # And all this goes over EAPOL/EAP_TLS
        self._session.send_response(eap_id, bytes(client_hello_record))
        self.sent_client_hello()

    def on_exit_tls_start(self, *args, **kwargs):
        self._k_send = "early data"

    def on_enter_wait_server_hello(self, *args, **kwargs):
        """
            "trigger": "rx_hello_retry_request", "source": WAIT_SH, "dest": START},
            {"trigger": "rx_server_hello", "source": WAIT_SH, "dest": WAIT_EE},
        """
        print(f"{self.state}: entry")
        # Can delete if nothing to be done while we wait
        # TODO: How about a reasonable timeout to trigger shutdown?
        print(f"{self.state}: TODO: How about a reasonable timeout to trigger shutdown?")

    def on_exit_wait_server_hello(self, *args, **kwargs):
        print(f"{self.state}: on_exit_wait_server_hello")
        self._k_recv = "handshake"

    def on_enter_wait_encrypted_extensions(self, *args, **kwargs):
        """
            {"trigger": "encrypted_extensions", "source": WAIT_EE, "dest": WAIT_FINISHED, "conditions": "using_psk"},
            {"trigger": "encrypted_extensions", "source": WAIT_EE, "dest": WAIT_CERT_CR, "conditions": "using_certificate"},
        """
        print(f"{self.state}: entry")
        # Immediate transition to next state
        self.encrypted_extensions()

    def on_enter_wait_certificate_request(self, *args, **kwargs):
        """
            {"trigger": "rx_certificate_request", "source": WAIT_CERT_CR, "dest": WAIT_CERT},
            {"trigger": "rx_certificate", "source": WAIT_CERT_CR, "dest": WAIT_CV},
        """
        print(f"{self.state}: entry")

        # TODO: How about a reasonable timeout to trigger shutdown?
        print(f"{self.state}: TODO: How about a reasonable timeout to trigger shutdown?")

        # Note.  The certificate request will be in the EAP-TLS frame sent over, so there really is not a wait, but might
        #        want to keep this standard as much as possible
        #
        #        Also, the TLS 1.2 (or 1.3) says if we do not get a certificate request, then we should still send a client
        #        certificate where the certificate is empty.  Look up and add the proper RFC quote here.
        pass

    def on_enter_wait_certificate(self, *args, **kwargs):
        """
            {"trigger": "rx_certificate", "source": WAIT_CERT, "dest": WAIT_CV},
        """
        print(f"{self.state}: entry")
        pass

    def on_enter_certificate_verify(self, *args, **kwargs):
        """
            {"trigger": "certificate_verified", "source": WAIT_CV, "dest": WAIT_FINISHED},
            {"trigger": "rx_certificate_request", "source": WAIT_CV, "dest": "="},
        """
        print(f"{self.state}: entry")
        if False:
            raise NotImplementedError(f"{self.state}: Server certificate verfication is not supported")

        # Signal that server certificate is okay
        self.certificate_verified()

    def rx_server_hello_done(self, *args, eap_id: Optional[int] = 256, **kwargs):
        """
        Server hello complete, lets send the following:

        Certificate*
        ClientKeyExchange
        CertificateVerify*
        [ChangeCipherSpec]
        Encrypted Handshake Message
        """
        # Construct the response.  It will most likely be larger than the minimum frame size
        # so we will need to fragment it

        # Now make a list of records
        certificate = self._client_certificate()
        key_exchange = self._client_key_exchange()
        verify = self._certificate_verify()
        finish, encrypted_data = self._client_finish((certificate, verify, key_exchange))

        pkt_data = b""
        for pkt in (certificate, key_exchange, verify, finish, encrypted_data):
            record = self._session.create_tls_handshake_record(pkt)
            pkt_data += bytes(record)
            print(f"Record: {record}, Data: {pkt_data} ")

        # TODO: Need to fragment this and send it.  Can we add that into the session send?
        # And all this goes over EAPOL/EAP_TLS
        self._session.send_response(eap_id, pkt_data)

    def _client_certificate(self) -> 'TLSCertificate':
        from tls_packet.auth.tls_certificate import TLSCertificate, ASN_1_Cert, ASN_1_CertList

        certificate = self.session.certificate.tbs_certificate_bytes if self.session.certificate is not None else b''
        ca_certificate = self.session.ca_certificate.tbs_certificate_bytes if self.session.ca_certificate is not None else b''
        pub_cert = ASN_1_Cert(certificate)
        ca_cert = ASN_1_Cert(ca_certificate)  # TODO: Need to support a list?
        cert_list = ASN_1_CertList([pub_cert, ca_cert])

        return TLSCertificate(cert_list, length=cert_list.length)

    def _client_key_exchange(self) -> 'TLSClientKeyExchange':
        from tls_packet.auth.tls_client_key_exchange import TLSClientKeyExchange
        # certificate = self.session.certificate.tbs_certificate_bytes if self.session.certificate is not None else b''
        # ca_certificate = self.session.ca_certificate.tbs_certificate_bytes if self.session.ca_certificate is not None else b''
        # pub_cert = ASN_1_Cert(certificate)
        # ca_cert = ASN_1_Cert(ca_certificate)  # TODO: Need to support a list?
        # cert_list = ASN_1_CertList([pub_cert, ca_cert])
        return TLSClientKeyExchange()

    def _certificate_verify(self) -> 'TLSCertificateVerify':
        from tls_packet.auth.tls_certificate_verify import TLSCertificateVerify
        # certificate = self.session.certificate.tbs_certificate_bytes if self.session.certificate is not None else b''
        # ca_certificate = self.session.ca_certificate.tbs_certificate_bytes if self.session.ca_certificate is not None else b''
        # pub_cert = ASN_1_Cert(certificate)
        # ca_cert = ASN_1_Cert(ca_certificate)  # TODO: Need to support a list?
        # cert_list = ASN_1_CertList([pub_cert, ca_cert])
        return TLSCertificateVerify()

    def _client_finish(self, additional_handshakes: List['TLSHandshake']) -> Tuple['TLSFinish', bytes]:
        from tls_packet.auth.tls_finish import TLSFinish
        finish = TLSFinish()

        additional_handshakes.append(finish)
        additional_records = [self._session.create_tls_handshake_record(pkt) for pkt in additional_handshakes]

        # Change cipher spec
        # certificate = self.session.certificate.tbs_certificate_bytes if self.session.certificate is not None else b''
        # ca_certificate = self.session.ca_certificate.tbs_certificate_bytes if self.session.ca_certificate is not None else b''
        # pub_cert = ASN_1_Cert(certificate)
        # ca_cert = ASN_1_Cert(ca_certificate)  # TODO: Need to support a list?
        # cert_list = ASN_1_CertList([pub_cert, ca_cert])
        return finish, b""

    def on_enter_wait_finished(self, *args, **kwargs):
        """
            {"trigger": "encrypted_extensions", "source": WAIT_EE, "dest": WAIT_FINISHED, "conditions": "using_psk"},
        """
        print(f"{self.state}: entry")
        pass
        self._k_send = "handshake"
        # TODO: This also will get called when the TLSCertificateRequest is encountered. Probably re-arm timeout is okay.
        # TODO: How about a reasonable timeout to trigger shutdown?
        print(f"{self.state}: TODO: How about a reasonable timeout to trigger shutdown?")

    def on_exit_wait_finished(self, *args, **kwargs):
        pass  # TODO: Handle exiting due to failure/timeout/alert/...
        self._k_send = self._k_recv = "application"

    def on_enter_connected(self, *args, **kwargs):
        """
            {"trigger": "rx_finished", "source": WAIT_FINISHED, "dest": CONNECTED},
        """
        print(f"{self.state}: entry")

    def on_enter_close(self, *args, **kwargs):
        """
            # Shutdown from any state shuts machine down
            {"trigger": "rx_alert", "source": "*", "dest": CLOSE, "unless": "inactive"},
        """
        print(f"{self.state}: entry")
        self._closed = True
        raise NotImplementedError(f"{self.state}: TODO: Not yet implemented")

    def build_state_graph(self, filename):
        """ Build a graph representation of the state machine """
        model = type('model', (object,), {})()
        GraphMachine(model=model, states=self.STATES,
                     title="Authorization State Machine",
                     transitions=self.TRANSITIONS,
                     queued=True,
                     show_conditions=True,
                     show_state_attributes=True,
                     initial=self.IDLE)
        model.get_graph().draw(filename, prog='dot')  # pylint: disable=no-member


if __name__ == '__main__':
    # Call this from the command line with the graphviz module for a pair of pictures
    TLSClientStateMachine(None).build_state_graph("tls_client_state_machine.png")
    TLSClientStateMachine(None).build_state_graph("tls_client_state_machine.svg")
