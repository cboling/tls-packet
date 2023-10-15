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

from typing import Union


class TLS:
    """
    TLS base class

                     The Transport Layer Security (TLS) Protocol
                                 Version 1.0 -> 1.2

         Handshake Protocol

              Client                                               Server

              ClientHello                  -------->
                                                              ServerHello
                                                             Certificate*
                                                       ServerKeyExchange*
                                                      CertificateRequest*
                                           <--------      ServerHelloDone
              Certificate*
              ClientKeyExchange
              CertificateVerify*
              [ChangeCipherSpec]
              Finished                     -------->
                                                       [ChangeCipherSpec]
                                           <--------             Finished
              Application Data             <------->     Application Data

            * Indicates optional or situation-dependent messages that are not
              always sent.

            The TLS Handshake Protocol is one of the defined higher-level clients
            of the TLS Record Protocol.  This protocol is used to negotiate the
            secure attributes of a session.  Handshake messages are supplied to
            the TLS record layer, where they are encapsulated within one or more
            TLSPlaintext structures, which are processed and transmitted as
            specified by the current active session state.

            TLS 1.0 - Released in 1999 and published as RFC 2246. This version of TLS was
                      very similar to SSL 3.0

            TLS 1.1 - Released in 2006 and published as RFC 4346.

                      According to RFC 4346, the major differences that exist in TLS 1.1
                      compared to TLS 1.0 include the following:

                        o The implicit Initialization Vector (IV) is replaced with an explicit

                        o Initialization Vector for protection against Cipher Block Chaining
                          (CBC) attacks.

                        o Padding error handling is modified to use bad_record_mac alert
                          rather than decryption_failed alert. Again, to protect against CBC
                          attacks.

                        o IANA registries are defined for protocol parameters.

                        o A premature close no longer causes a session to be non-resumable.

                        o Additional notes were added regarding new attacks and a number of
                          clarifications and editorial improvements were made.

            TLS 1.2 - Released in 2008 and published as RFC 5246.

                      TLS 1.2 is currently the most used version of TLS and has made several
                      improvements in security compared to TLS 1.1. According to RFC 4346, the
                      major differences that exist in TLS 1.2 when compared to TLS 1.1 include
                      the following:

                        o The MD5/SHA-1 combination in the pseudorandom function (PRF) is replaced
                          with SHA-256 with the option to use the cipher-suite-specified PRFs.

                        o The MD5/SHA-1 combination in the digitally-signed element is replaced
                          with a single hash which is negotiated during the handshake.

                        o Improvements to the client's and server's ability to specify the
                          accepted hash and signature algorithms.

                        o Support for authenticated encryption for other data modes

                        o TLS extensions and AES cipher suites were added

                        o Tightened up various requirements

                      The greater enhancement in encryption of TLS 1.2 allows it to use more secure
                      hash algorithms such as SHA-256 as well as advanced cipher suites that support
                      elliptical curve cryptography.

            TLS 1.3 - Released in August 2018 and published as RFC 8446

                      TLS 1.3 offers several improvements over earlier versions, most notably a
                      faster TLS handshake and simpler, more secure cipher suites. Zero Round-Trip
                      Time (0-RTT) key exchanges further streamline the TLS handshake. Together,
                      these changes provide better performance and stronger security.


                            The Transport Layer Security (TLS) Protocol
                                          Version 1.3

                             Client                               Server

                      Initial Handshake:
                          ClientHello
                          + key_share           -------->
                                                                    ServerHello
                                                                    + key_share
                                                          {EncryptedExtensions}
                                                          {CertificateRequest*}
                                                                 {Certificate*}
                                                           {CertificateVerify*}
                                                                     {Finished}
                                               <--------    [Application Data*]
                          {Certificate*}
                          {CertificateVerify*}
                          {Finished}           -------->
                                               <--------     [NewSessionTicket]
                          [Application Data]   <------->     [Application Data]

                      Subsequent Handshake:
                         ClientHello
                         + key_share*
                         + pre_shared_key      -------->
                                                                    ServerHello
                                                               + pre_shared_key
                                                                   + key_share*
                                                          {EncryptedExtensions}
                                                                     {Finished}
                                               <--------    [Application Data*]
                         {Finished}            -------->
                         [Application Data]    <------->     [Application Data]
    """
    _code = tuple()

    @classmethod
    def get_by_code(cls, code: Union[int, bytes]) -> Union['TLS', None]:
        if isinstance(code, int):
            code = code.to_bytes(length=2, byteorder='big')

        return next((tls_obj for tls_obj in (TLSv1_0(), TLSv1_1(), TLSv1_2(), TLSv1_3())
                     if code == bytes(tls_obj)), None)

    def __int__(self) -> int:
        return int.from_bytes(bytes(self), 'big')

    def __bytes__(self) -> bytes:
        return b''.join(self._code)

    def __eq__(self, other: 'TLS') -> bool:
        return self.__bytes__() == other

    def __gt__(self, other: 'TLS') -> bool:
        return self._code > other._code

    def __lt__(self, other: 'TLS') -> bool:
        return other._code > self._code

    def __ge__(self, other: 'TLS') -> bool:
        return self._code >= other._code

    def __le__(self, other: 'TLS') -> bool:
        return other._code >= self._code


class TLSv1(TLS):
    """ TLSv1.0 """
    _code = (b'\x03', b'\x01')

    def __str__(self):
        return "TLSv1.0"


TLSv1_0 = TLSv1
SSLv3 = TLSv1


class TLSv1_1(TLS):
    """ TLSv1.1 """
    _code = (b'\x03', b'\x02')

    def __str__(self):
        return "TLSv1.1"


class TLSv1_2(TLS):
    """ TLSv1.3 """
    _code = (b'\x03', b'\x03')

    def __str__(self):
        return "TLSv1.2"


class TLSv1_3(TLS):
    """ TLSv1.3 """
    _code = (b'\x03', b'\x04')

    def __str__(self):
        return "TLSv1.3"
