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
    """ TLS base class """
    _code = tuple()

    @classmethod
    def get_by_code(cls, code: bytes) -> Union['TLS', None]:
        for tls_obj in (TLSv1_0(), TLSv1_1(), TLSv1_2(), TLSv1_3()):
            if code == bytes(tls_obj):
                return tls_obj
        return None

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
