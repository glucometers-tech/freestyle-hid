# SPDX-FileCopyrightText: © 2020 The freestyle-hid Authors
# SPDX-License-Identifier: Apache-2.0


class HIDError(Exception):
    """Errors related to the HID access process."""


class ConnectionError(Exception):
    """Errors related to Session establishment."""


class EncryptionHandshakeError(ConnectionError):
    """Errors related to encryption handshake."""


class ChecksumError(Exception):
    """Errors related to the transmission checksums."""


class CommandError(Exception):
    """Errors related to the command stream."""


class EncryptionNotInitialized(CommandError):
    """Device needs encryption handshake."""


class MissingFreeStyleKeys(Exception):
    """The freestyle-hid-keys package is missing."""

    def __init__(self):
        super().__init__(
            "The freestyle-hid-keys package is missing, please install it from PyPi."
            " You can install freestyle-hid[encryption] to select the encryption keys"
            " package as an extra dependency."
        )
