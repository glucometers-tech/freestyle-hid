<!--
SPDX-FileCopyrightText: 2013 The freestyle-hid Authors

SPDX-License-Identifier: Apache-2.0
-->

# Python library to interact with Abbott FreeStyle devices

This repository includes a library and some tools to interact with Abbott
FreeStyle devices that use their
[shared HID protocol](https://protocols.glucometers.tech/abbott/shared-hid-protocol.html).

## Tools

There are a number of tools that interact with either the devices or with
USB session captures that are installed together when selecting the `tools`
extra:

 * `freestyle-hid-console` allows sending direct text messages to a compatible
   device on the console;
 * `freestyle-extract-chatter` can produce a "chatter" file based on a capture
   of an USB session, either from Linux or Windows.
 * `freestyle-encrypted-setup-extract` is an experimental tool to extract the
   encryption parameters of devices using the encrypted protocol (e.g. Libre2).

## Development

If you want to contribute code, please note that the target language
is Python 3.7, and that the style to follow is for the most part PEP8
compatible.

To set up your development environment follow these guidelines:

```shell
$ git clone https://github.com/glucometers-tech/freestyle-hid.git
$ cd glucometerutils
$ python3 -m venv --python=python3.7
$ . venv/bin/activate
$ pip install -e .[dev,tools]
$ pre-commit install
```
