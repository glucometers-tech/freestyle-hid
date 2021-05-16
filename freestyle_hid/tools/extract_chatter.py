#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-FileCopyrightText: © 2020 The freestyle-hid Authors
#
# SPDX-License-Identifier: Apache-2.0

import logging
import sys
import textwrap
from typing import BinaryIO, Optional

import click
import click_log
import construct
import usbmon
import usbmon.chatter
import usbmon.pcapng
import usbmon.support.hid
from usbmon.tools import _utils

logger = logging.getLogger()
click_log.basic_config(logger)

_KEEPALIVE_TYPE = 0x22

_UNENCRYPTED_TYPES = (
    0x01,
    0x04,
    0x05,
    0x06,
    0x0C,
    0x0D,
    0x14,
    0x15,
    0x33,
    0x34,
    0x35,
    0x71,
    _KEEPALIVE_TYPE,
)

_ENCRYPTION_SETUP_TYPES = (0x14, 0x33)

_START_AUTHORIZE_CMD = 0x11
_CHALLENGE_CMD = 0x16
_CHALLENGE_RESPONSE_CMD = 0x17
_CHALLENGE_ACCEPTED_CMD = 0x18

_ABBOTT_VENDOR_ID = 0x1A61
_LIBRE2_PRODUCT_ID = 0x3950

_ENCRYPTED_MESSAGE = construct.Struct(
    encrypted_message=construct.Bytes(64 - 1 - 4 - 4),
    sequence_number=construct.Int32ul,
    mac=construct.Int32ul,
)


@click.command()
@click_log.simple_verbosity_option(logger, "--vlog")
@click.option(
    "--device-address",
    help=(
        "Device address (busnum.devnum) of the device to extract capture"
        " of. If none provided, device descriptors will be relied on."
    ),
    type=_utils.DeviceAddressType(),
)
@click.option(
    "--encrypted-protocol / --no-encrypted-protocol",
    default=False,
    help=(
        "Whether to expect encrypted protocol in the capture."
        " Ignored if the device descriptors are present in the capture."
    ),
)
@click.option(
    "--verbose-encryption-setup / --no-verbose-encryption-setup",
    default=False,
    help=(
        "Whether to parse encryption setup commands and printing their component"
        " together with the raw messsage."
    ),
)
@click.option(
    "--print-keepalive / --no-print-keepalive",
    default=False,
    help=(
        "Whether to print the keepalive messages sent by the device. "
        "Keepalive messages are usually safely ignored."
    ),
)
@click.argument(
    "pcap-file",
    type=click.File(mode="rb"),
)
def main(
    *,
    device_address: Optional[usbmon.addresses.DeviceAddress],
    encrypted_protocol: bool,
    verbose_encryption_setup: bool,
    print_keepalive: bool,
    pcap_file: BinaryIO,
) -> None:
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    session = usbmon.pcapng.parse_stream(pcap_file, retag_urbs=False)

    if not device_address:
        possible_addresses = list(session.find_devices_by_ids(_ABBOTT_VENDOR_ID, None))
        if len(possible_addresses) > 1:
            possible_addresses_str = ", ".join(
                str(address) for address in possible_addresses
            )
            raise click.UsageError(
                f"Multiple Abbott devices found, please select one of {possible_addresses_str}"
            )
        elif len(possible_addresses) == 0:
            raise click.UsageError("No Abbott devices found.")
        else:
            (device_address,) = possible_addresses

    if device_address not in session.device_descriptors:
        logging.warning(
            f"Unable to find device {device_address} in the capture's descriptors."
            " Assuming non-encrypted protocol.",
        )
    else:
        descriptor = session.device_descriptors[device_address]
        assert descriptor.vendor_id == _ABBOTT_VENDOR_ID

        if descriptor.product_id == _LIBRE2_PRODUCT_ID:
            encrypted_protocol = True

    for packet in usbmon.support.hid.select(session, device_address=device_address):
        assert packet.report_content
        message_type = packet.report_id

        if message_type == _KEEPALIVE_TYPE and not print_keepalive:
            continue

        message_metadata = []

        if encrypted_protocol and message_type not in _UNENCRYPTED_TYPES:
            # With encrypted communication, the length of the message is also encrypted,
            # and all the packets use the full 64 bytes. So instead, we extract what
            # metadata we can.
            parsed = _ENCRYPTED_MESSAGE.parse(packet.report_content)
            message_metadata.extend(
                [f"SEQUENCE_NUMBER={parsed.sequence_number}", f"MAC={parsed.mac:04x}"]
            )

            message_type_str = f"x{message_type:02x}"
            message = parsed.encrypted_message
        elif verbose_encryption_setup and message_type in _ENCRYPTION_SETUP_TYPES:
            message_length = packet.report_content[0]
            message_end_idx = 1 + message_length
            message = packet.report_content[1:message_end_idx]

            if message[0] == _START_AUTHORIZE_CMD:
                message_metadata.append("START_AUTHORIZE")
            elif message[0] == _CHALLENGE_CMD:
                message_metadata.append("CHALLENGE")
                challenge = message[1:9]
                iv = message[9:16]
                message_metadata.append(f"CHALLENGE={challenge.hex()}")
                message_metadata.append(f"IV={iv.hex()}")
            elif message[0] == _CHALLENGE_RESPONSE_CMD:
                message_metadata.append("CHALLENGE_RESPONSE")
                encrypted_challenge = message[1:17]
                challenge_mac = message[18:26]
                message_metadata.append(
                    f"ENCRYPTED_CHALLENGE={encrypted_challenge.hex()}"
                )
                message_metadata.append(f"MAC={challenge_mac.hex()}")
            elif message[0] == _CHALLENGE_ACCEPTED_CMD:
                message_metadata.append("CHALLENGE_ACCEPTED")

            message_metadata.append(f"RAW_LENGTH={message_length}")
            message_type_str = f" {message_type:02x}"
        else:
            message_length = packet.report_content[0]
            message_metadata.append(f"LENGTH={message_length}")
            message_end_idx = 1 + message_length
            message_type_str = f" {message_type:02x}"
            message = packet.report_content[1:message_end_idx]

        if message_metadata:
            metadata_string = "\n".join(
                textwrap.wrap(
                    " ".join(message_metadata), width=80, break_long_words=False
                )
            )
            print(metadata_string)

        print(
            usbmon.chatter.dump_bytes(
                packet.direction,
                message,
                prefix=f"[{message_type_str}]",
                print_empty=True,
            ),
            "\n",
        )


if __name__ == "__main__":
    main()
