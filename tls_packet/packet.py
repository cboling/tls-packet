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
import time

import copy
from typing import List, Tuple, Union, Iterable, Optional, Any


PARSE_ALL = int(1e6)     # Parse all packet layers


class DecodeError(Exception):
    """ Raised when decode/parsing of a frame fails """


# TODO: Specialize DecodeError.  TruncationError, IllegalValue, ...

class SerializeError(Exception):
    """ Raised when serialization/packing of a frame fails """


def get_time_ns() -> int:
    if sys.hexversion >= 0x03070000:
        # Available in python 3.7 and later
        return time.monotonic_ns()
    else:
        return int(time.monotonic() * 1e9)


class Packet:
    """ Base packet class """
    def __init__(self,
                 *args,
                 original_frame: Optional[bytes] = b'',
                 layers: Optional[Iterable['Packet']] = None,
                 timestamp: Optional[Union[int, None]] = None, **kwargs):

        if len(args):
            # By now, all derived classes should have consumed any extra positional arguments.  Perhaps we missed one or had a type?
            print(f"TODO: Reached base Packet class with additional arguments: {len(args)}")

        if len(kwargs):
            # By now, all derived classes should have consumed any extre keywords.  Perhaps we missed one or had a type?
            print(f"TODO: Reached base Packet class with unknown keywords: {kwargs}")

        self._timestamp:int = timestamp or get_time_ns()           # Creation or capture timestamp
        self._original_frame: bytes = copy.copy(original_frame)    # Frame as originally received

        # Order list of encapsulated layer that have been decoded
        layers: List['Packet'] = layers or []
        self._layers = [pkt for  pkt in layers]

    def __repr__(self):
        sublayers = f"[{len(self._layers)}: {repr(self._layers)}]"
        return f"{self.__class__.__qualname__}: Sublayers: {sublayers}"

    def __str__(self):
        return repr(self)

    def __iadd__(self, layer: 'Packet') -> 'Packet':
        """ Append a packet layer """
        return self.add_layer(layer)

    def add_layer(self,  layer: 'Packet') -> 'Packet':
        self._layers.append(layer)
        return self

    def __eq__(self, other) -> bool:
        """ Are two layers identical in content """
        return bytes(self) == bytes(other)

    @property
    def name(self) -> str:
        """ Packet layer name """
        return self.__class__.__qualname__

    @property
    def layers(self) -> Tuple['Packet']:
        return tuple(self._layers)

    @property
    def payload_data(self) -> bytes:
        """ Return sublayers as bytes"""
        data = b''
        for layer in self._layers:
            data += layer.pack()
        return data

    def has_layer(self, name: str, after: Optional['Packet'] = None) -> bool:
        return self.get_layer(name, after=after) is not None

    def get_layer(self, name: str, after: Optional[Union['Packet', None]] = None) -> Optional[Union['Packet', None]]:
        index = 0

        # Search for an existing layer to start our 'get' afterwards?
        if after is not None:
            for layer in self._layers:
                index += 1
                if layer == after:
                    break

        for layer in self._layers[index:]:
            if layer.name == name:
                return layer

        return None

    @staticmethod
    def parse(frame: bytes, *args, max_depth: Optional[int] = PARSE_ALL, **kwargs) -> Union['Packet', None]:
        """
        Recursively parse a frame of bytes into a packet layer, but limit to at most 'max_depth' more layers

        As you recurse, call the sub-packet's parse() method with 'max_depth - 1'
        """
        raise NotImplementedError("Implement in your derived class")

    def pack(self, payload: Optional[bytes] = b'') -> bytes:
        return self.payload_data + payload

    def __bytes__(self) -> bytes:
        return self.pack()


class PacketPayload(Packet):
    """
    Unparsed or unparseable packet payload data

    Do not confuse this with any 'payload' that a layer may want to hide or keep track of for other reasons
    """
    def __init__(self, frame, *args, **kwargs):
        super().__init__(*args, original_frame=frame, **kwargs)

    @staticmethod
    def parse(frame: bytes, *args, **kwargs) -> Union['Packet', None]:
        """ Recursively parse a frame of bytes into a packet layer, but limit to at most 'max_depth' more layers """
        return PacketPayload(original_frame=frame, **kwargs)

    def pack(self, payload: Optional[bytes] = b'') -> bytes:
        return self._original_frame + payload

    def __repr__(self):
        return f"{self.__class__.__qualname__}: {len(self._original_frame)} bytes"

    def __eq__(self, other: Any) -> bool:
        """ Are two layers identical in content """
        return self._original_frame == bytes(other)
