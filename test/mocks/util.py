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

import os
import unittest


def assertGeneratedFrameEquals(test_case: unittest.TestCase, frame: bytes, ref: str) -> None:
    if not isinstance(frame, bytes):
        test_case.fail(f"Invalid type for frame. Expected: 'bytes', got: {type(frame)}")

    str_frame = frame.hex().upper()
    ref = ref.upper()
    if str_frame != ref:
        test_case.fail(f"Mismatch:{os.linesep}Reference: {len(ref):>4}: {ref}{os.linesep}Generated: {len(str_frame):>4}: {str_frame}")

# 010000AB0303000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000017C02CC030009FCCA9CCA8CCAAC02BC02F009EC024C028006BC023C0270067C00AC014C009C013009D009C003D003C01000054000B000403000102000A000C000A001D0017001E001900180016000000170000000D0030002E040305030603080708080809080A080B080408050806040105010601030302030301020103020202040205020602
# 010000AB0303000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00002EC02CC030009FCCA9CCA8CCAAC02BC02F009EC024C028006BC023C0270067C00AC014C009C013009D009C003D003C01000054000B000403000102000A000C000A001D0017001E001900180016000000170000000D0030002E040305030603080708080809080A080B080408050806040105010601030302030301020103020202040205020602
