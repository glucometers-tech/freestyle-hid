# SPDX-FileCopyrightText: © 2019 The freestyle-hid Authors
# SPDX-License-Identifier: Apache-2.0
"""Tests for the common FreeStyle functions.."""

# pylint: disable=protected-access,missing-docstring

import unittest

from freestyle_hid import _session


class TestFreeStyle(unittest.TestCase):
    def test_outgoing_command(self):
        """Test the generation of a new outgoing message."""

        self.assertEqual(
            b"\0\x17\7command\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            _session._FREESTYLE_MESSAGE.build(
                {"message_type": 23, "command": b"command"}
            ),
        )
