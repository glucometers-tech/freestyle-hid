#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2019 The freestyle-hid Authors
# SPDX-License-Identifier: Apache-2.0
"""CLI tool to send messages through FreeStyle HID protocol."""

import logging
import pathlib
import sys
from typing import Optional

import click
import click_log

import freestyle_hid
from freestyle_hid import models

logger = logging.getLogger()
click_log.basic_config(logger)


@click.command()
@click_log.simple_verbosity_option(logger, "--vlog")
@click.option(
    "--text-command-type",
    "-c",
    type=int,
    default=0x60,
    help="Message type for text commands sent to the device.",
)
@click.option(
    "--text-reply-type",
    "-r",
    type=int,
    default=0x60,
    help="Message type for text replies received from the device.",
)
@click.option(
    "--product-id",
    "-p",
    type=int,
    help="Optional product ID (in alternative to the device path)",
)
@click.option(
    "--encoding",
    "-e",
    type=str,
    help="Encoding to use to decode commands returned by the meter",
    default="ascii",
)
@click.option(
    "--encrypted-protocol / --no-encrypted-protocol",
    default=False,
    help=(
        "Whether to use the encrypted protocol to communicate to the device."
        " This is necessary to talk to Libre2 glucometers."
    ),
)
@click.argument(
    "device-path",
    type=click.Path(exists=True, dir_okay=False, writable=True, allow_dash=True),
    callback=lambda ctx, param, value: pathlib.Path(value)
    if value and value != "-"
    else None,
    required=False,
)
@click.argument(
    "command",
    type=str,
    required=False,
)
def main(
    *,
    text_command_type: int,
    text_reply_type: int,
    product_id: Optional[int],
    device_path: Optional[pathlib.Path],
    encoding: str,
    encrypted_protocol: bool,
    command: Optional[str],
):
    if not product_id and not device_path:
        raise click.UsageError(
            "One of --product-id or DEVICE_PATH need to be provided."
        )

    if product_id == models.FREESTYLE_LIBRE_2:
        # No matter if the user requested it or not, in this case we know
        # the protocol needs to be encrypted.
        encrypted_protocol = True

    session = freestyle_hid.Session(
        product_id,
        device_path,
        text_command_type,
        text_reply_type,
        encoding=encoding,
        encrypted=encrypted_protocol,
    )

    session.connect()

    if command is not None:
        try:
            print(session.send_text_command(bytes(command, "ascii")))
        except freestyle_hid.CommandError as error:
            print(f"! {error!r}")

        return

    while True:
        if sys.stdin.isatty():
            command = input(">>> ")
        else:
            command = input()
            print(f">>> {command}")

        try:
            print(session.send_text_command(bytes(command, "ascii")))
        except freestyle_hid.CommandError as error:
            print(f"! {error!r}")


if __name__ == "__main__":
    main()
