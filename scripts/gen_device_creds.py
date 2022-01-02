#!/usr/bin/env python3

"""
Copyright 2021 Dean Hall.  See LICENSE for details.

A command-line tool to drive ham_ident
to generate device credential files

Device files go in an application-specific folder.
"""

import argparse
import getpass
import sys

from ham_ident import *


WARNING = """WARNING: This tool should not be used for meaningful cryptography!
In this project, we are using the keypair to sign certificates and
authenticate messages for recreational/amateur radio communication.
"""


def main(args: argparse.Namespace) -> None:
    print(WARNING)
    print("Enter device info [*=required].")
    person_ident = HamCredential.get_ident()
    app_name = _input_required("App name*: ")
    ssid = _input_required("SSID*: ")

    if not bool(args.force) and HamCredential.exists(app_name):
        print("Credential exists.  Exiting.")
    else:
        passphrase = _input_passphrase()
        HamCredentialBuilder.gen_device_credentials(ssid, passphrase, app_name)

def _input_required(prompt: str) -> str:
    n = ""
    while len(n) == 0:
        n = input(prompt)
    return n

def _input_passphrase() -> bytes:
    pass1 = pass2 = ""
    while pass1 == "":
        pass1 = getpass.getpass("Private key encryption passphrase: ")
    while pass2 != pass1:
        pass2 = getpass.getpass("Repeat passphrase: ")
    return pass1.encode()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-F", "--force", action="store_true", help='Overwrite existing credentials')
    args = parser.parse_args()
    main(args)
