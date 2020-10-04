#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: © 2019 The usbmon-tools Authors
# SPDX-FileCopyrightText: © 2019 The freestyle-hid Authors
#
# SPDX-License-Identifier: Apache-2.0

import logging
import sys
from typing import BinaryIO, Sequence

import click
import click_log
import construct
import usbmon
import usbmon.pcapng

logger = logging.getLogger()
click_log.basic_config(logger)


_SERIAL_NUMBER_RESPONSE_TYPE = 0x06
_ENCRYPTION_SETUP_REQ_TYPE = 0x14
_ENCRYPTION_SETUP_RESP_TYPE = 0x33


_START_AUTHORIZE_CMD = 0x11
_CHALLENGE_CMD = 0x16
_CHALLENGE_RESPONSE_CMD = 0x17


_ABBOTT_VENDOR_ID = 0x1A61
_LIBRE2_PRODUCT_ID = 0x3950

_SERIAL_NO = construct.Struct(
    message_type=construct.Const(_SERIAL_NUMBER_RESPONSE_TYPE, construct.Byte),
    length=construct.Const(14, construct.Byte),
    serial_number=construct.PaddedString(13, "ascii"),
    termination=construct.Const(0, construct.Byte),
)

_CHALLENGE = construct.Struct(
    message_type=construct.Const(_ENCRYPTION_SETUP_RESP_TYPE, construct.Byte),
    length=construct.Const(16, construct.Byte),
    subcmd=construct.Const(_CHALLENGE_CMD, construct.Byte),
    challenge=construct.Bytes(8),
    iv=construct.Bytes(7),
)

_CHALLENGE_RESPONSE = construct.Struct(
    message_type=construct.Const(_ENCRYPTION_SETUP_REQ_TYPE, construct.Byte),
    length=construct.Const(26, construct.Byte),
    subcmd=construct.Const(_CHALLENGE_RESPONSE_CMD, construct.Byte),
    challenge_response_encrypted=construct.Bytes(16),
    const=construct.Const(1, construct.Byte),
    mac=construct.Bytes(8),
)


@click.command()
@click_log.simple_verbosity_option(logger, "--vlog")
@click.option(
    "--device-address",
    help=(
        "Device address (busnum.devnum) of the device to extract capture"
        " of. If none provided, device descriptors will be relied on."
    ),
)
@click.argument(
    "pcap-files",
    type=click.File(mode="rb"),
    nargs=None,
)
def main(*, device_address: str, pcap_files: Sequence[BinaryIO]):
    if sys.version_info < (3, 7):
        raise Exception("Unsupported Python version, please use at least Python 3.7.")

    for pcap_file in pcap_files:
        session = usbmon.pcapng.parse_stream(pcap_file, retag_urbs=False)

        if not device_address:
            for descriptor in session.device_descriptors.values():
                if (
                    descriptor.vendor_id == _ABBOTT_VENDOR_ID
                    and descriptor.product_id == _LIBRE2_PRODUCT_ID
                ):
                    if device_address and device_address != descriptor.address:
                        raise Exception(
                            "Multiple Libre2 devices present in capture, please"
                            " provide a --device-address flag."
                        )
                    device_address = descriptor.address
        else:
            device_address = descriptor.address

        if device_address in session.device_descriptors:
            descriptor = session.device_descriptors[device_address]
            assert descriptor.vendor_id == _ABBOTT_VENDOR_ID
            assert descriptor.product_id == _LIBRE2_PRODUCT_ID

        serial_number = "UNKNOWN"
        challenge = "UNKNOWN"
        iv = "UNKNOWN"
        encrypted_challenge = "UNKNOWN"
        mac = "UNKNOWN"

        for first, second in session.in_pairs():
            # Ignore stray callbacks/errors.
            if not first.type == usbmon.constants.PacketType.SUBMISSION:
                continue

            if not first.address.startswith(f"{device_address}."):
                # No need to check second, they will be linked.
                continue

            if first.xfer_type == usbmon.constants.XferType.INTERRUPT:
                pass
            elif (
                first.xfer_type == usbmon.constants.XferType.CONTROL
                and not first.setup_packet
                or first.setup_packet.type == usbmon.setup.Type.CLASS  # type: ignore
            ):
                pass
            else:
                continue

            if first.direction == usbmon.constants.Direction.OUT:
                packet = first
            else:
                assert second is not None
                packet = second

            if not packet.payload:
                continue

            assert len(packet.payload) >= 2

            message_type = packet.payload[0]

            if message_type == _SERIAL_NUMBER_RESPONSE_TYPE:
                obj = _SERIAL_NO.parse(packet.payload)
                serial_number = obj.serial_number
            elif (
                message_type == _ENCRYPTION_SETUP_RESP_TYPE
                and packet.payload[2] == _CHALLENGE_CMD
            ):
                obj = _CHALLENGE.parse(packet.payload)
                challenge = obj.challenge.hex()
                iv = obj.iv.hex()
            elif (
                message_type == _ENCRYPTION_SETUP_REQ_TYPE
                and packet.payload[2] == _CHALLENGE_RESPONSE_CMD
            ):
                obj = _CHALLENGE_RESPONSE.parse(packet.payload)
                encrypted_challenge = obj.challenge_response_encrypted.hex()
                mac = obj.mac.hex()

        print(f"{serial_number},{challenge},{iv},{encrypted_challenge},{mac}")


if __name__ == "__main__":
    main()
