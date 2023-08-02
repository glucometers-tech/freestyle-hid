# SPDX-FileCopyrightText: © 2013 The freestyle-hid Authors
# SPDX-License-Identifier: Apache-2.0

import csv
import logging
import pathlib
import random
import re
from typing import AnyStr, Callable, Iterator, Optional, Sequence, Tuple

import construct

from ._exceptions import (
    ChecksumError,
    CommandError,
    EncryptionHandshakeError,
    EncryptionNotInitialized,
    MissingFreeStyleKeys,
)
from ._freestyle_encryption import SpeckCMAC, SpeckEncrypt
from ._hidwrapper import HidWrapper

try:
    from freestyle_keys import libre2 as libre2_keys

    _HAS_LIBRE2_KEYS = True
except ImportError:
    _HAS_LIBRE2_KEYS = False

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

_HID_REPORT = construct.Struct(
    number=construct.Byte, content=construct.Padded(64, construct.GreedyBytes)
)

_FREESTYLE_MESSAGE = construct.Struct(
    message_type=construct.Byte,
    command=construct.Padded(
        55,  # command can only be up to 54 bytes, but one is used for length.
        construct.Prefixed(construct.Byte, construct.GreedyBytes),
    ),
    iv_counter=construct.Padding(4),
    mac=construct.Int32ul,
)

_CHALLENGE_MESSAGE = construct.Struct(
    subcmd=construct.Const(0x16, construct.Byte),
    reader_nonce=construct.Bytes(8),
    iv=construct.BytesInteger(7, signed=False, swapped=False),
)

_CHALLENGE_RESPONSE_NOMAC_RAW = construct.Struct(
    message_type=construct.Const(_ENCRYPTION_SETUP_COMMAND, construct.Byte),
    length=construct.Const(0x1A, construct.Byte),
    response_subcmd=construct.Const(0x17, construct.Byte),
    response=construct.Bytes(16),
    const1=construct.Const(0x01, construct.Byte),
)

_CHALLENGE_RESPONSE_RAW = construct.Struct(
    response=_CHALLENGE_RESPONSE_NOMAC_RAW,
    mac=construct.Int64ul,
)

_CHALLENGE_ACCEPTED_MESSAGE = construct.Struct(
    subcmd=construct.Const(0x18, construct.Byte),
    encrypted_nonces=construct.Bytes(16),
    iv=construct.BytesInteger(7, signed=False, swapped=False),
    mac=construct.Int64ul,
)

_TEXT_COMPLETION_RE = re.compile(b"CMD (?:OK|Fail!)")
_TEXT_REPLY_FORMAT = re.compile(
    b"^(?P<message>.*)CKSM:(?P<checksum>[0-9A-F]{8})\r\n"
    b"CMD (?P<status>OK|Fail!)\r\n$",
    re.DOTALL,
)

_MULTIRECORDS_FORMAT = re.compile(
    b"^(?P<message>.+\r\n)(?P<count>[0-9]+),(?P<checksum>[0-9A-F]{8})\r\n$", re.DOTALL
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
        encoding: str = "ascii",
        encrypted: bool = False,
    ) -> None:
        if encrypted and not _HAS_LIBRE2_KEYS:
            raise MissingFreeStyleKeys()

        self._handle = HidWrapper.open(device_path, ABBOTT_VENDOR_ID, product_id)
        self._text_message_type = text_message_type
        self._text_reply_message_type = text_reply_message_type
        self._encoding = encoding
        self._encrypted_protocol = encrypted

    def encryption_handshake(self):
        self.send_command(0x05, b"")
        response = self.read_response()
        assert response[0] == 0x06
        serial = response[1][:13]

        crypt = SpeckCMAC(libre2_keys.AUTHORIZATION_ENCRYPTION_KEY)
        auth_enc_key = crypt.derive("AuthrEnc".encode(), serial)
        auth_enc = SpeckEncrypt(auth_enc_key)
        crypt = SpeckCMAC(libre2_keys.AUTHORIZATION_MAC_KEY)
        auth_mac_key = crypt.derive("AuthrMAC".encode(), serial)
        auth_mac = SpeckCMAC(auth_mac_key)

        self.send_command(_ENCRYPTION_SETUP_COMMAND, b"\x11")
        (response_type, response_bytes) = self.read_response()

        if response_type != _ENCRYPTION_SETUP_RESPONSE:
            raise EncryptionHandshakeError(
                f"Unexpected response type: {response_type:02x}"
            )

        challenge_response = _CHALLENGE_MESSAGE.parse(response_bytes)
        host_nonce = random.randbytes(8)

        encrypted_challenge_response = auth_enc.encrypt(
            challenge_response.iv, challenge_response.reader_nonce + host_nonce
        )

        raw_response_nomac = _CHALLENGE_RESPONSE_NOMAC_RAW.build(
            {"response": encrypted_challenge_response}
        )
        response_mac = auth_mac.sign(raw_response_nomac)
        raw_response = _CHALLENGE_RESPONSE_RAW.build(
            {
                "response": {"response": encrypted_challenge_response},
                "mac": response_mac,
            }
        )

        self._write_hid(raw_response)
        (response_type, response_bytes) = self.read_response()

        if response_type != _ENCRYPTION_SETUP_RESPONSE:
            raise EncryptionHandshakeError(
                f"Unexpected response type: {response_type:02x}"
            )

        acceptance_response = _CHALLENGE_ACCEPTED_MESSAGE.parse(response_bytes)

        # We need to reconstruct the raw message, so we include the expected type and size.
        mac = auth_mac.sign(b"\x33\x22" + response_bytes[:24])

        if mac != acceptance_response.mac:
            raise EncryptionHandshakeError(
                f"Challenge acceptance has incorrect MAC! Expected {mac:016x} received {acceptance_response.mac:016x}."
            )

        decoded_nonces = auth_enc.decrypt(
            acceptance_response.iv, acceptance_response.encrypted_nonces
        )

        if decoded_nonces != host_nonce + challenge_response.reader_nonce:
            raise EncryptionHandshakeError("Decrypted nonces do not match expectation.")

        context_key = serial + challenge_response.reader_nonce + host_nonce

        logging.debug(f"Context key established: {context_key.hex()}")

        crypt = SpeckCMAC(libre2_keys.SESSION_ENCRYPTION_KEY)
        ses_enc_key = crypt.derive("SessnEnc".encode(), context_key)
        crypt = SpeckCMAC(libre2_keys.SESSION_MAC_KEY)
        ses_mac_key = crypt.derive("SessnMAC".encode(), context_key)
        self.crypt_enc = SpeckEncrypt(ses_enc_key)
        self.crypt_mac = SpeckCMAC(ses_mac_key)

    def connect(self):
        """Open connection to the device, starting the knocking sequence."""
        if self._encrypted_protocol:
            self.encryption_handshake()
        self.send_command(_INIT_COMMAND, b"")
        response = self.read_response()
        if not _is_init_reply(response):
            raise ConnectionError(
                f"Connection error: unexpected message %{response[0]:02x}:{response[1].hex()}"
            )

    def encrypt_message(self, packet: bytes):
        output = bytearray(packet)
        # 0xFF IV is actually 0, because of some weird padding
        encrypted = self.crypt_enc.encrypt(0xFF, packet[1:56])
        output[1:56] = encrypted
        # Not giving a f**k about the IV counter for now
        output[56:60] = bytes(4)
        mac = self.crypt_mac.sign(output[0:60])
        output[60:64] = int.to_bytes(mac, 8, byteorder="little", signed=False)[4:]
        return bytes(output)

    def decrypt_message(self, packet: bytes):
        output = bytearray(packet)
        mac = self.crypt_mac.sign(packet[:60])
        mac = int.to_bytes(mac, 8, byteorder="little", signed=False)[4:]
        assert mac == packet[60:64]
        iv = int.from_bytes(packet[56:60], "big", signed=False) << 8
        output[1:56] = self.crypt_enc.decrypt(iv, packet[1:56])
        return bytes(output)

    def _write_hid(self, packet: bytes, hid_report: int = 0) -> None:
        usb_packet = _HID_REPORT.build({"number": hid_report, "content": packet})
        logging.debug(f"Sending packet: {usb_packet!r}")
        self._handle.write(usb_packet)

    def send_command(self, message_type: int, command: bytes, encrypted: bool = False):
        """Send a raw command to the device.

        Args:
          message_type: The first byte sent with the report to the device.
          command: The command to send out the device.
        """

        message = _FREESTYLE_MESSAGE.build(
            {"message_type": message_type, "command": command, "mac": 0}
        )

        if (
            self._encrypted_protocol
            and message_type not in _ALWAYS_UNENCRYPTED_MESSAGES
        ):
            message = self.encrypt_message(message)

        self._write_hid(message)

    def read_response(self, encrypted: bool = False) -> Tuple[int, bytes]:
        """Read the response from the device and extracts it."""
        usb_packet = self._handle.read()

        logging.debug(f"Read packet: {usb_packet!r}")

        assert usb_packet
        message_type = usb_packet[0]

        if (
            self._encrypted_protocol
            and message_type not in _ALWAYS_UNENCRYPTED_MESSAGES
        ):
            usb_packet = self.decrypt_message(usb_packet)

        message_length = usb_packet[1]
        message_end_idx = 2 + message_length
        message_content = usb_packet[2:message_end_idx]

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
            raise EncryptionNotInitialized("Device encryption not initialized.")

        if _is_encryption_setup_error(message):
            raise CommandError("Device encryption initialization failed.")

        return message

    def _send_text_command_raw(self, command: bytes) -> bytes:
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

        return message

    def send_text_command(self, command: bytes) -> str:
        return self._send_text_command_raw(command).decode(self._encoding, "replace")

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
        message = self._send_text_command_raw(command)
        logging.debug(f"Received multi-record message:\n{message!r}")
        if message == b"Log Empty\r\n":
            return iter(())

        match = _MULTIRECORDS_FORMAT.search(message)
        if not match:
            raise CommandError(repr(message))

        records_raw = match.group("message")
        _verify_checksum(records_raw, match.group("checksum"))

        # Decode here with replacement; the software does not deal with UTF-8
        # correctly, and appears to truncate incorrectly the strings.
        records_str = records_raw.decode(self._encoding, "replace")

        logging.debug(f"Received multi-record string: {records_str}")

        return csv.reader(records_str.split("\r\n"))
