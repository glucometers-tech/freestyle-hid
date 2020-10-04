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
@click.argument(
    "device-path",
    type=click.Path(exists=True, dir_okay=False, writable=True, allow_dash=False),
    callback=lambda ctx, param, value: pathlib.Path(value) if value else None,
    required=False,
)
def main(
    *,
    text_command_type: int,
    text_reply_type: int,
    product_id: Optional[int],
    device_path: Optional[pathlib.Path],
):
    if not product_id and not device_path:
        raise click.UsageError(
            "One of --product-id or DEVICE_PATH need to be provided."
        )

    session = freestyle_hid.Session(
        product_id, device_path, text_command_type, text_reply_type
    )

    session.connect()

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
