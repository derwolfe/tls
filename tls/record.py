# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

from enum import Enum

from characteristic import attributes

from tls import _constructs


@attributes(['major', 'minor'])
class ProtocolVersion(object):
    """
    An object representing a ProtocolVersion struct.
    """


@attributes(['type', 'version', 'fragment'])
class TLSPlaintext(object):
    """
    An object representing a TLSPlaintext struct.
    """


@attributes(['type', 'version', 'fragment'])
class TLSCompressed(object):
    """
    An object representing a TLSCompressed struct.
    """


@attributes(['type', 'version', 'fragment'])
class TLSCiphertext(object):
    """
    An object representing a TLSCiphertext struct.
    """


class ContentType(Enum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


def parse_tls_plaintext(bytes):
    """
    Parse a ``TLSPlaintext`` struct.

    :param bytes: the bytes representing the input.
    :return: TLSPlaintext object.
    """
    construct = _constructs.TLSPlaintext.parse(bytes)
    return TLSPlaintext(
        type=ContentType(construct.type),
        version=ProtocolVersion(
            major=construct.version.major,
            minor=construct.version.minor),
        fragment=construct.fragment)


def parse_tls_compressed(bytes):
    """
    Parse a ``TLSCompressed`` struct.

    :param bytes: the bytes representing the input.
    :return: TLSCompressed object.
    """
    construct = _constructs.TLSCompressed.parse(bytes)
    return TLSCompressed(
        type=ContentType(construct.type),
        version=ProtocolVersion(
            major=construct.version.major,
            minor=construct.version.minor),
        fragment=construct.fragment)


def parse_tls_ciphertext(bytes):
    """
    Parse a ``TLSCiphertext`` struct.

    :param bytes: the bytes representing the input.
    :return: TLSCiphertext object.
    """
    construct = _constructs.TLSCiphertext.parse(bytes)
    return TLSCiphertext(
        type=ContentType(construct.type),
        version=ProtocolVersion(
            major=construct.version.major,
            minor=construct.version.minor),
        fragment=construct.fragment)
