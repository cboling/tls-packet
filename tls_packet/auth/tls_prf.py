# Mostly from https://github.com/nealyip/tls_client_handshake_pure_python
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
This file implements the TLS Pseudo-Random Function as specified by Section 5
of RFC 5246 (https://tools.ietf.org/html/rfc5246#section-5). The section
states:

.. code-block:: none

    The TLS record layer uses a keyed Message Authentication Code (MAC) to
    protect message integrity.  The cipher suites defined in this document use
    a construction known as HMAC, described in [HMAC], which is based on a hash
    function.  Other cipher suites MAY define their own MAC constructions, if
    needed.

    In addition, a construction is required to do expansion of secrets into
    blocks of data for the purposes of key generation or validation.  This
    pseudorandom function (PRF) takes as input a secret, a seed, and an
    identifying label and produces an output of arbitrary length.

    In this section, we define one PRF, based on HMAC.  This PRF with the
    SHA-256 hash function is used for all cipher suites defined in this
    document and in TLS documents published prior to this document when TLS 1.2
    is negotiated.  New cipher suites MUST explicitly specify a PRF and, in
    general, SHOULD use the TLS PRF with SHA-256 or a stronger standard hash
    function.

    First, we define a data expansion function, P_hash(secret, data), that uses
    a single hash function to expand a secret and seed into an arbitrary
    quantity of output:

        P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
        HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ...

    where + indicates concatenation.

    A() is defined as:

        A(0) = seed A(i) = HMAC_hash(secret, A(i-1))

    P_hash can be iterated as many times as necessary to produce the required
    quantity of data.  For example, if P_SHA256 is being used to create 80
    bytes of data, it will have to be iterated three times (through A(3)),
    creating 96 bytes of output data; the last 16 bytes of the final iteration
    will then be discarded, leaving 80 bytes of output data.

    TLS's PRF is created by applying P_hash to the secret as:

        PRF(secret, label, seed) = P_<hash>(secret, label + seed)

    The label is an ASCII string.  It should be included in the exact form it
    is given without a length byte or trailing null character.  For example,
    the label "slithy toves" would be processed by hashing the following bytes:

        73 6C 69 74 68 79 20 74 6F 76 65 73
"""

from __future__ import absolute_import, division, print_function

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC


def _p_hash(hash_algorithm, secret, seed, output_length):
    """
    A seed expansion function that uses a single hash function to expand a
    secret and seed into the number of bytes specified by output_length.
    """
    result = bytearray()
    i = 1
    while len(result) < output_length:
        h = HMAC(secret, hash_algorithm, default_backend())
        h.update(_a(secret, hash_algorithm, i, seed))
        h.update(seed)
        result.extend(h.finalize())
        i += 1
    return bytes(result[:output_length])


def _a(secret, hash_algorithm, n, seed):
    """
    a() is defined as:
        a(0) = seed
        a(i) = HMAC_hash(secret, A(i-1))
    """
    if n == 0:
        return seed
    else:
        h = HMAC(secret, hash_algorithm, default_backend())
        h.update(_a(secret, hash_algorithm, n - 1, seed))
        return h.finalize()


def prf(secret, label, seed, hash_algorithm, output_length):
    """
    A construction to expand secrets into blocks of data for the purposes of
    key generation or validation.

    This pseudo-random function (PRF) takes as input a secret, a seed, an
    identifying label and a hash algorithm and produces an output of length
    specified in output_length.

    :param secret: Secret key as ``bytes``.  The key should be randomly
        generated bytes and is recommended to be equal in length to the
        digest_size of the hash function chosen. You must keep the key secret.
    :type secret: :py:class:`bytes`

    :param label: An ASCII string.
    :type label: :py:class:`bytes`

    :param seed: The seed as ``bytes``.
    :type label: :py:class:`bytes`

    :param hash_algorithm: The hash algorithm to use with HMAC.
    :type hash_algorithm: a
        :py:class:`cryptography.hazmat.primitives.hashes.HashAlgorithm`
        provider.

    :param output_length: The number of bytes to expand the seed into.
    :type output_length: :py:class:`int`
    """
    return _p_hash(hash_algorithm, secret, label + seed, output_length)
