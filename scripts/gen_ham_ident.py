#!/usr/bin/env python3

"""
Copyright 2017 Dean Hall.  See LICENSE for details.

A command-line tool to drive ham_ident
to generate personal credential files

Personal files go in the ham_ident application folder.

References
----------

ISO 3166 Alpha-2 Country codes:
    https://www.nationsonline.org/oneworld/country_code_list.htm
"""

import argparse
import getpass
import sys

from ham_ident import *


WARNING = """WARNING: This tool should not be used for meaningful cryptography!
In this project, we are using the keypair to sign certificates and
authenticate messages for recreational/amateur radio communication.
"""


def main(args: argparse.Namespace):
    print(WARNING)
    if not bool(args.force) and HamCredential.exists():
        print("Credential exists.  Exiting.")
    else:
        ident = _input_person_info()
        passphrase = _input_passphrase()
        HamCredentialBuilder.gen_personal_credentials(ident, passphrase)

def _input_person_info() -> HamIdentity:
    print("Enter data for an X.509 certificate [*=required].")
    person_info = {}
    person_info["commonName"] = _input_required("Given name*: ")
    person_info["emailAddress"] = _input_required("Email*: ")
    person_info["pseudonym"] = str.upper(_input_required("Callsign*: "))
    person_info["stateOrProvinceName"] = input("State or province name: ")
    person_info["postalCode"] = input("Postal/zip code: ")
    person_info["countryName"] = input("Country code (ISO Alpha-2): ")
    return HamIdentity(**person_info)

def _input_required(prompt) -> str:
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
