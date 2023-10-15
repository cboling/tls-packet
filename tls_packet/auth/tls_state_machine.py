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
import sys
from cryptography.x509 import Certificate, Extension, Extensions, ObjectIdentifier, Version, Name
from transitions import Machine, State
from transitions.extensions import GraphMachine
from typing import Optional, Tuple, List, Any, Union

from tls_packet.auth.cipher_suites import CipherSuite
from tls_packet.auth.security_params import SecurityParameters, TLSCompressionMethod
from tls_packet.auth.tls import TLSv1_2
from tls_packet.auth.tls_certificate import TLSCertificate, ASN_1_Cert
from tls_packet.auth.tls_certificate_request import TLSCertificateRequest
from tls_packet.auth.tls_named_curve import ECCurveType, NamedCurve, NamedCurveType
from tls_packet.auth.tls_record import TLSChangeCipherSpecRecord, TLSChangeCipherSpecType
from tls_packet.auth.tls_server_hello import TLSServerHello
from tls_packet.auth.tls_server_key_exchange import TLSServerKeyExchange
from tls_packet.auth.tls_signature_algorithm import RsaPkcs1Md5Sha1


class TLSClientStateMachine(Machine):
    """
    TLS Client State Machine: From RFC-8446: Appendix A.1

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
                       =                 WAIT_SH ----+
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
                       =                  | [Send EndOfEarlyData]
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
        {"trigger": "rx_eap_failure", "source": "*", "dest": CLOSE, "unless": "inactive"},
        {"trigger": "close", "source": "*", "dest": CLOSE},
    ]

    def __init__(self, session: 'TLSClient'):
        super().__init__(model=self, states=self.STATES, transitions=self.TRANSITIONS,
                         queued=True, initial=self.INITIAL, ignore_invalid_triggers=False)
        self._session = session
        self._closed = False
        self._client_certificate_requested = False
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
                self._client_certificate_requested = True

            elif any(packet.has_layer(ke_type) for ke_type in ("TLSServerKeyExchangeECDH",
                                                               "TLSServerKeyExchangeDH",
                                                               "TLSServerKeyExchangeRSA")):
                print("Rx TLSServerKeyExchange")
                layer = packet.get_layer("TLSServerKeyExchangeECDH") or \
                        packet.get_layer("TLSServerKeyExchangeDH") or \
                        packet.get_layer("TLSServerKeyExchangeRSA")
                self.rx_server_key_exchange(layer)

            elif packet.has_layer("TLSServerHelloDone"):
                print("Rx TLSServerHelloDone")
                self.rx_server_hello_done(eap_id=eap_id)

            elif packet.has_layer("TLSFinish"):
                print("Rx TLSFinish")
                self.rx_finished(eap_id=eap_id, frame=packet.get_layer("TLSFinish"))

            # elif any(packet.has_layer(layer) for layer in ("",)):
            #     print(f"Rx {packet}: No special trigger attached, but we decode it anyway here")
            else:
                raise ValueError(f"TLSClientStateMachine: {self.state}: Unsupported TLSRecord Type: {packet}")

        else:
            raise ValueError(f"TLSClientStateMachine: {self.state}: Unsupported Packet Type: {packet}")

    @property
    def session(self) -> 'TLSClient':
        return self._session

    def rx_security_parameters(self, active: Optional[bool] = True) -> SecurityParameters:
        return self._session.rx_security_parameters(active=active)

    def tx_security_parameters(self, active: Optional[bool] = True) -> SecurityParameters:
        return self._session.tx_security_parameters(active=active)

    def client_certificate_requested(self) -> bool:
        return self._client_certificate_requested

    def using_psk(self, *args, **kwargs) -> bool:
        print(f"TLSClientStateMachine: 'using_psk' condition is currently hardcoded to 'False'")
        return False

    def using_certificate(self, *args, **kwargs) -> bool:
        print(f"TLSClientStateMachine: 'using_certificates' condition is currently hardcoded to 'True'")
        return True

    def inactive(self) -> bool:
        return self.state != self.CLOSE

    def on_enter_tls_start(self, *args, eap_id: Optional[int] = 256, **kwargs):
        """
            {"trigger": "start", "source": START, "dest": "="},
        """
        print(f"{self.state}: entry")
        self._k_send = ""
        self._k_recv = ""

        # Construct and send Client Hello
        from tls_packet.auth.tls_client_hello import TLSClientHello
        client_hello = TLSClientHello(self.session)

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
        # Exiting due to Rx of Server hello
        hello = kwargs.pop("frame", None)
        if isinstance(hello, TLSServerHello):
            # Save security parameters from the hello

            rx_parms = self.rx_security_parameters(active=False)
            tx_parms = self.tx_security_parameters(active=False)

            # TODO: Encode what we can. Many are done in following records
            cipherSuite = CipherSuite.get_from_id(self.session.tls_version, hello.cipher_suite)

            if cipherSuite is None:
                print(f"ServerHello: Unsupported cipher suite selected: {hello.cipher_suite:#04x}")
                self.close()    # TODO : handle this better
                return

            rx_parms.cipher_suite = tx_parms.cipher_suite = cipherSuite
            tx_parms.compression_algorithm = rx_parms.compression_algorithm = hello.compression_method  # TLSCompressionMethod
            tx_parms.server_random = rx_parms.server_random = hello.random_bytes

            if not self._session.set_tls_version(hello.version):
                print(f"Server TLS Version {hello.version} is not supported", file=sys.stderr)
                # TODO: Do we send an alert
                self.close()
                return

            if hello.compression_method != TLSCompressionMethod.NULL_METHOD:
                raise NotImplementedError("Server wants compression but we do not support it yet")

        self._k_recv = "handshake"

    def on_enter_wait_encrypted_extensions(self, *args, **kwargs):
        """
            {"trigger": "encrypted_extensions", "source": WAIT_EE, "dest": WAIT_FINISHED, "conditions": "using_psk"},
            {"trigger": "encrypted_extensions", "source": WAIT_EE, "dest": WAIT_CERT_CR, "conditions": "using_certificate"},

        This is a TLS v1.3-only state
        """
        # frame=packet.get_layer("TLSServerHello")  <- On initial entry. Available if needed
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

            We should be passing in the server certificate on initial entry
        """
        print(f"{self.state}: entry")

        cert = kwargs.pop("frame", None)
        if isinstance(cert, TLSCertificate):
            certificates: Tuple[ASN_1_Cert] = cert.certificates
            print(f"Received {len(certificates)} certificates")

            if len(certificates) == 0:
                raise NotImplementedError(f"{self.state}: No certificate. Send an alert message")

            first_cert: ASN_1_Cert = certificates[0]
            x509_cert = first_cert.x509_certificate

            # Save security parameters from the server certificate
            rx_parms = self.rx_security_parameters(active=False)
            tx_parms = self.tx_security_parameters(active=False)

            rx_parms.server_certificate = tx_parms.server_certificate = x509_cert

            # Save off the server certificate here as this is a common point
            if self.session.verify_server_certificate:
                # TODO: Need to decode full list of certs provided...
                not_valid_after: 'datetime' = x509_cert.not_valid_after
                not_valid_before: 'datetime' = x509_cert.not_valid_before
                signature: bytes = x509_cert.signature
                signature_algorithm_oid: ObjectIdentifier = x509_cert.signature_algorithm_oid
                signature_hash_algorithm: Union['SHA256', Any] = x509_cert.signature_hash_algorithm
                issuer: Name = x509_cert.issuer
                subject: Name = x509_cert.subject
                extensions: Extensions = x509_cert.extensions
                tbs_certificate_bytes: bytes = x509_cert.tbs_certificate_bytes
                version: Version = x509_cert.version

                raise NotImplementedError(f"{self.state}: Server certificate verification is not supported")

            # Signal that server certificate is okay
            self.certificate_verified()

    def rx_server_key_exchange(self, key_exchange: TLSServerKeyExchange):
        # Validate signature
        # TODO: Make validation of the ServerKeyExchange optional in the future

        rx_parms = self.rx_security_parameters(active=False)
        # tx_parms = self.tx_security_parameters(active=False)

        signature_algorithm = rx_parms.cipher_suite.signature_algorithm(rx_parms)

        if self.session.verify_server_key_exchange:
            if not signature_algorithm.verify(key_exchange.signature, key_exchange.server_params):
                print("ServerKeyExchange: Public Key is not valid", file=sys.stderr)   # TODO: handle correctly
                # TODO: self.close()
                # return

        # Save security parameters from the hello if needed
        # TODO: Save stuff here

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
        pkt_data = b""

        # Now make a list of records to add to the finish
        if self._client_certificate_requested:
            client_certificate = self._client_certificate()
            record = self._session.create_tls_handshake_record(client_certificate)
            pkt_data += bytes(record)
            print(f"Record: {record}, Data Len: {len(pkt_data)} bytes")

        key_exchange = self._client_key_exchange()
        record = self._session.create_tls_handshake_record(key_exchange)
        pkt_data += bytes(record)
        print(f"Record: {record}, Data Len: {len(pkt_data)} bytes")

        verify = self._certificate_verify(pkt_data)
        record = self._session.create_tls_handshake_record(verify)
        pkt_data += bytes(record)
        print(f"Record: {record}, Data Len: {len(pkt_data)} bytes")

        change_cipher_spec = TLSChangeCipherSpecRecord(TLSChangeCipherSpecType.CHANGE_CIPHER_SPEC)
        pkt_data += bytes(change_cipher_spec)
        print(f"Record: {change_cipher_spec}, Data Len: {len(pkt_data)} bytes")

        finish = self._client_finish(pkt_data)
        pkt_data += bytes(finish)

        # TODO: Need to fragment this and send it.  Can we add that into the session send?
        # And all this goes over EAPOL/EAP_TLS
        self._session.send_response(eap_id, pkt_data)

    def _client_certificate(self) -> 'TLSCertificate':
        from tls_packet.auth.tls_certificate import TLSCertificate, ASN_1_Cert, ASN_1_CertList

        # TODO: Allow more than a single client and ca_certificate.  Also, if no certificates, send empty record
        #       per RFC.
        certificate = self.session.certificate.tbs_certificate_bytes if self.session.certificate is not None else b''
        ca_certificate = self.session.ca_certificate.tbs_certificate_bytes if self.session.ca_certificate is not None else b''
        pub_cert = ASN_1_Cert(certificate)
        ca_cert = ASN_1_Cert(ca_certificate)
        cert_list = ASN_1_CertList([pub_cert, ca_cert])

        return TLSCertificate(cert_list, length=cert_list.length)

    def _client_key_exchange(self) -> 'TLSClientKeyExchange':
        from tls_packet.auth.tls_client_key_exchange import TLSClientKeyExchange
        # Look up what the server sent us
        #
        # If RSA is used as a key exchange method, then the client selects a set of keys,
        # encrypts tme, and sends them on.  If DH was usd as a key exchange method, both sides
        # would agree on Z and that would be used as the key. However, TLS needs more.
        #
        rx_parms = self.rx_security_parameters(active=False)
        tx_parms = self.tx_security_parameters(active=False)

        # pre_master_secr

        server_certificate = rx_parms.server_certificate

        # TODO: What do we need from server_key_exchange.  Save to Rx_parms
        server_key_exchange = next((record.get_layer("TLSServerKeyExchange") for record in self.session.received_handshake_records
                                    if record.has_layer("TLSServerKeyExchange")), None)

        return TLSClientKeyExchange.create(self.session)

        server_certificate = security_params.server_certificate
        server_public_key = security_params.server_public_key

        client_public_key = security_params.client_public_key
        client_private_key = security_params.client_private_key

        key_exchange_type = security_params.cipher_suite.key_exchange_type
        signature = b""

        # public_key = self._session.public_key
        # private_key = self._session.private_key
        # self._session.keyh
        # self.public_key = keys.get("public")
        # self.private_key = keys.get("private")

        # certificate = self.session.certificate.tbs_certificate_bytes if self.session.certificate is not None else b''
        # ca_certificate = self.session.ca_certificate.tbs_certificate_bytes if self.session.ca_certificate is not None else b''
        # pub_cert = ASN_1_Cert(certificate)
        # ca_cert = ASN_1_Cert(ca_certificate)  # TODO: Need to support a list?
        # cert_list = ASN_1_CertList([pub_cert, ca_cert])
        return TLSClientKeyExchange()

    def _certificate_verify(self, new_client_records: bytes) -> 'TLSCertificateVerify':
        from tls_packet.auth.tls_certificate_verify import TLSCertificateVerify

        # TODO: Eventually do hash on packet send so we do not have to re-pack

        data_so_far = "".join(record.pack() for record in self.session._client_handshake_records_sent)
        data_so_far += "".join(record.pack() for record in self.session._server_handshake_records_received)
        data_so_far += new_client_records

        rx_parms = self.rx_security_parameters(active=False)

        return TLSCertificateVerify.create(data_so_far, rx_parms)

    def _client_finish(self, new_client_records: bytes) -> 'TLSFinish':
        # TODO: Eventually do hash on packet send so we do not have to re-pack
        data_so_far = "".join(record.pack() for record in self.session._client_handshake_records_sent)
        data_so_far += "".join(record.pack() for record in self.session._server_handshake_records_received)
        data_so_far += new_client_records

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
        return finish

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
        # TODO: Anything else?

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
