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

import ham_ident


WARNING = """WARNING: This tool does not protect the private key!
You should not use this keypair for meaningful cryptography!
In this project, we are using the keypair to authenticate
messages for recreational/amateur radio communication.
"""


def main(args):
    print(WARNING)
    if not bool(args.force):
        assert not ham_ident.HamCredential.exists(), \
            "Exiting to prevent overwriting existing credentials."
    _gen_personal_credentials()

def _gen_personal_credentials():
    ident = _input_person_info()
    passphrase = _input_passphrase()
    ham_ident.gen_personal_credentials(ident, passphrase)

def _input_person_info():
    print("Enter data for an X.509 certificate [*=required].")
    person_info = {}
    person_info["givenName"] = _input_required("Given name*: ")
    person_info["emailAddress"] = _input_required("Email*: ")
    person_info["pseudonym"] = _input_required("Callsign*: ")
    person_info["surname"] = input("Surname: ")
    person_info["stateOrProvinceName"] = input("State or province name: ")
    person_info["postalCode"] = input("Postal/zip code: ")
    person_info["countryName"] = input("Country code (ISO Alpha-2): ")
    return HamIdentity(**person_info)

def _input_required(prompt):
    n = ""
    while len(n) == 0:
        n = input(prompt)
    return n

def _input_passphrase():
    pass1 = getpass.getpass("Private key encryption passphrase: ")
    pass2 = ""
    while pass2 != pass1:
        pass2 = getpass.getpass("Repeat passphrase: ")
    return pass1.encode()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-F", "--force", default=False, help='Overwrite existing files')
    args = parser.parse_args()
    main(args)
