# SPDX-FileCopyrightText: © 2013 The freestyle-hid Authors
# SPDX-License-Identifier: Apache-2.0

import csv
import logging
import pathlib
import re
from typing import AnyStr, Callable, Iterator, Optional, Sequence, Tuple

import construct

from ._exceptions import ChecksumError, CommandError
from ._hidwrapper import HidWrapper

ABBOTT_VENDOR_ID = 0x1A61

_INIT_COMMAND = 0x01
_INIT_RESPONSE = 0x71

_KEEPALIVE_RESPONSE = 0x22
_UNKNOWN_MESSAGE_RESPONSE = 0x30

_ENCRYPTION_SETUP_COMMAND = 0x14
_ENCRYPTION_SETUP_RESPONSE = 0x33

_ALWAYS_UNENCRYPTED_MESSAGES = (
    _INIT_COMMAND,
    0x04,
    0x05,
    0x06,
    0x0C,
    0x0D,
    _ENCRYPTION_SETUP_COMMAND,
    0x15,
    _ENCRYPTION_SETUP_RESPONSE,
    0x34,
    0x35,
    _INIT_RESPONSE,
    _KEEPALIVE_RESPONSE,
)


def _create_matcher(
    message_type: int, content: Optional[bytes]
) -> Callable[[Tuple[int, bytes]], bool]:
    def _matcher(message: Tuple[int, bytes]) -> bool:
        return message[0] == message_type and (content is None or content == message[1])

    return _matcher


_is_init_reply = _create_matcher(_INIT_RESPONSE, b"\x01")
_is_keepalive_response = _create_matcher(_KEEPALIVE_RESPONSE, None)
_is_unknown_message_error = _create_matcher(_UNKNOWN_MESSAGE_RESPONSE, b"\x85")
_is_encryption_missing_error = _create_matcher(_ENCRYPTION_SETUP_RESPONSE, b"\x15")
_is_encryption_setup_error = _create_matcher(_ENCRYPTION_SETUP_RESPONSE, b"\x14")

_FREESTYLE_MESSAGE = construct.Struct(
    hid_report=construct.Const(0, construct.Byte),
    message_type=construct.Byte,
    command=construct.Padded(
        63,  # command can only be up to 62 bytes, but one is used for length.
        construct.Prefixed(construct.Byte, construct.GreedyBytes),
    ),
)

_FREESTYLE_ENCRYPTED_MESSAGE = construct.Struct(
    hid_report=construct.Const(0, construct.Byte),
    message_type=construct.Byte,
    command=construct.Padded(
        63,  # command can only be up to 62 bytes, but one is used for length.
        construct.GreedyBytes,
    ),
)

_TEXT_COMPLETION_RE = re.compile(b"CMD (?:OK|Fail!)")
_TEXT_REPLY_FORMAT = re.compile(
    b"^(?P<message>.*)CKSM:(?P<checksum>[0-9A-F]{8})\r\n"
    b"CMD (?P<status>OK|Fail!)\r\n$",
    re.DOTALL,
)

_MULTIRECORDS_FORMAT = re.compile(
    "^(?P<message>.+\r\n)(?P<count>[0-9]+),(?P<checksum>[0-9A-F]{8})\r\n$", re.DOTALL
)


def _verify_checksum(message: AnyStr, expected_checksum_hex: AnyStr) -> None:
    """Calculate the simple checksum of the message and compare with expected.

    Args:
      message: (str) message to calculate the checksum of.
      expected_checksum_hex: hexadecimal string representing the checksum
        expected to match the message.

    Raises:
      InvalidChecksum: if the message checksum calculated does not match the one
        received.
    """
    expected_checksum = int(expected_checksum_hex, 16)
    if isinstance(message, bytes):
        all_bytes = (c for c in message)
    else:
        all_bytes = (ord(c) for c in message)

    calculated_checksum = sum(all_bytes)

    if expected_checksum != calculated_checksum:
        raise ChecksumError(
            f"Invalid checksum, expected {expected_checksum}, calculated {calculated_checksum}"
        )


class Session:
    def __init__(
        self,
        product_id: Optional[int],
        device_path: Optional[pathlib.Path],
        text_message_type: int,
        text_reply_message_type: int,
    ) -> None:
        self._handle = HidWrapper.open(device_path, ABBOTT_VENDOR_ID, product_id)

        self._text_message_type = text_message_type
        self._text_reply_message_type = text_reply_message_type

    def connect(self):
        """Open connection to the device, starting the knocking sequence."""
        self.send_command(_INIT_COMMAND, b"")
        response = self.read_response()
        if not _is_init_reply(response):
            raise ConnectionError(
                f"Connection error: unexpected message %{response[0]:02x}:{response[1].hex()}"
            )

    def send_command(self, message_type: int, command: bytes, encrypted: bool = False):
        """Send a raw command to the device.

        Args:
          message_type: The first byte sent with the report to the device.
          command: The command to send out the device.
        """
        if encrypted:
            assert message_type not in _ALWAYS_UNENCRYPTED_MESSAGES
            meta_construct = _FREESTYLE_ENCRYPTED_MESSAGE
        else:
            meta_construct = _FREESTYLE_MESSAGE

        usb_packet = meta_construct.build(
            {"message_type": message_type, "command": command}
        )

        logging.debug(f"Sending packet: {usb_packet!r}")
        self._handle.write(usb_packet)

    def read_response(self, encrypted: bool = False) -> Tuple[int, bytes]:
        """Read the response from the device and extracts it."""
        usb_packet = self._handle.read()

        logging.debug(f"Read packet: {usb_packet!r}")

        assert usb_packet
        message_type = usb_packet[0]

        if not encrypted or message_type in _ALWAYS_UNENCRYPTED_MESSAGES:
            message_length = usb_packet[1]
            message_end_idx = 2 + message_length
            message_content = usb_packet[2:message_end_idx]
        else:
            message_content = usb_packet[1:]

        # hidapi module returns a list of bytes rather than a bytes object.
        message = (message_type, bytes(message_content))

        # There appears to be a stray number of 22 01 xx messages being returned
        # by some devices after commands are sent. These do not appear to have
        # meaning, so ignore them and proceed to the next. These are always sent
        # unencrypted, so we need to inspect them before we decide what the
        # message content is.
        if _is_keepalive_response(message):
            return self.read_response(encrypted=encrypted)

        if _is_unknown_message_error(message):
            raise CommandError("Invalid command")

        if _is_encryption_missing_error(message):
            raise CommandError("Device encryption not initialized.")

        if _is_encryption_setup_error(message):
            raise CommandError("Device encryption initialization failed.")

        return message

    def send_text_command(self, command: bytes) -> str:
        """Send a command to the device that expects a text reply."""
        self.send_command(self._text_message_type, command)

        # Reply can stretch multiple buffers
        full_content = b""
        while True:
            message_type, content = self.read_response()

            logging.debug(
                f"Received message: type {message_type:02x} content {content.hex()}"
            )

            if message_type != self._text_reply_message_type:
                raise CommandError(
                    f"Message type {message_type:02x}: content does not match expectations: {content!r}"
                )

            full_content += content

            if _TEXT_COMPLETION_RE.search(full_content):
                break

        match = _TEXT_REPLY_FORMAT.search(full_content)
        if not match:
            raise CommandError(repr(full_content))

        message = match.group("message")
        _verify_checksum(message, match.group("checksum"))

        if match.group("status") != b"OK":
            raise CommandError(repr(message) or "Command failed")

        # If there is anything in the response that is not ASCII-safe, this is
        # probably in the patient name. The Windows utility does not seem to
        # validate those, so just replace anything non-ASCII with the correct
        # unknown codepoint.
        return message.decode("ascii", "replace")

    def query_multirecord(self, command: bytes) -> Iterator[Sequence[str]]:
        """Queries for, and returns, "multirecords" results.

        Multirecords are used for querying events, readings, history and similar
        other data out of a FreeStyle device. These are comma-separated values,
        variable-length.

        The validation includes the general HID framing parsing, as well as
        validation of the record count, and of the embedded records checksum.

        Args:
          command: The text command to send to the device for the query.

        Returns:
          A CSV reader object that returns a record for each line in the
          reply buffer.
        """
        message = self.send_text_command(command)
        logging.debug(f"Received multirecord message:\n{message}")
        if message == "Log Empty\r\n":
            return iter(())

        match = _MULTIRECORDS_FORMAT.search(message)
        if not match:
            raise CommandError(message)

        records_str = match.group("message")
        _verify_checksum(records_str, match.group("checksum"))

        logging.debug(f"Received multi-record string: {records_str}")

        return csv.reader(records_str.split("\r\n"))
