# SPDX-FileCopyrightText: © 2020 The freestyle-hid Authors
# SPDX-License-Identifier: Apache-2.0


class HIDError(Exception):
    """Errors related to the HID access process."""


class ConnectionError(Exception):
    """Errors related to Session establishment."""


class ChecksumError(Exception):
    """Errors related to the transmission checksums."""


class CommandError(Exception):
    """Errors related to the command stream."""
