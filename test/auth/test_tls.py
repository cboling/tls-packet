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

import unittest

from tls_packet.auth.tls import SSLv3, TLS, TLSv1, TLSv1_0, TLSv1_1, TLSv1_2, TLSv1_3


class TestTLS(unittest.TestCase):

    def test_tls_operations(self):
        self.assertEqual(TLSv1(), TLSv1_0())
        self.assertEqual(TLSv1_0(), TLSv1())
        self.assertEqual(TLSv1(), SSLv3())
        self.assertEqual(SSLv3(), TLSv1())

        self.assertTrue(TLSv1() <= TLSv1_0())
        self.assertTrue(TLSv1_0() <= TLSv1())
        self.assertTrue(TLSv1() <= SSLv3())
        self.assertTrue(SSLv3() <= TLSv1())

        self.assertTrue(TLSv1() >= TLSv1_0())
        self.assertTrue(TLSv1_0() >= TLSv1())
        self.assertTrue(TLSv1() >= SSLv3())
        self.assertTrue(SSLv3() >= TLSv1())

        self.assertTrue(TLSv1() < TLSv1_1())
        self.assertTrue(TLSv1_1() < TLSv1_2())
        self.assertTrue(TLSv1_2() < TLSv1_3())

        self.assertTrue(TLSv1() <= TLSv1_1())
        self.assertTrue(TLSv1_1() <= TLSv1_2())
        self.assertTrue(TLSv1_2() <= TLSv1_3())

        self.assertTrue(TLSv1_1() > TLSv1())
        self.assertTrue(TLSv1_2() > TLSv1_1())
        self.assertTrue(TLSv1_3() > TLSv1_2())

        self.assertTrue(TLSv1_1() >= TLSv1())
        self.assertTrue(TLSv1_2() >= TLSv1_1())
        self.assertTrue(TLSv1_3() >= TLSv1_2())


if __name__ == '__main__':
    unittest.main()
