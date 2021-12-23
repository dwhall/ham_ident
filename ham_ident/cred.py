"""
Copyright 2021 Dean Hall.  See LICENSE for details.
"""


import os.path

from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from . import app_data
from .ident import HamIdentity


APP_NAME = "ham_ident"


class HamCredentialError(Exception):
    pass


class HamCredential():
    """HamCredential is an x509 certificate containing HamIdentity fields."""
    FN_TAIL = "_cred.pem"

    @classmethod
    def exists(cls, app_name, callsign):
        try:
            return os.path.exists(cls.get_fn(app_name, callsign))
        except AssertionError:
            return False

    @classmethod
    def get_fn(cls, app_name, callsign):
        app_path = app_data.get_app_data_path(app_name)
        return os.path.join(app_path, callsign + cls.FN_TAIL)

    @classmethod
    def get_ident(cls, app_name, callsign) -> HamIdentity:
        if not cls.exists(app_name, callsign):
            raise HamCredentialError("Credential file does not exist")
        pem_data = open(HamCredential.get_fn(app_name, callsign), "rb").read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        fields = {}
        for oid in HamIdentity.REQUIRED_OIDS:
            val = cert.subject.get_attributes_for_oid(oid)[0].value
            if val:
                fields[oid._name] = val
        for oid in HamIdentity.OPTIONAL_OIDS:
            val = cert.subject.get_attributes_for_oid(oid)[0].value
            if val:
                fields[oid._name] = val
        return HamIdentity(**fields)


class HamJsonCredential(HamCredential):
    """HamJsonCredential is a JSON file containing HamIdentity fields and a public key."""
    FN_TAIL = "_cred.json"

    @classmethod
    def get_ident(cls, app_name) -> HamIdentity:
        with open(cls.get_fn()) as f:
            json_info = json.load(f)
        fields = {}
        for oid in HamIdentity.REQUIRED_OIDS:
            fields[oid._name] = json_info.get(oid._name, "")
        for oid in HamIdentity.OPTIONAL_OIDS:
            fields[oid._name] = json_info.get(oid._name, "")
        return HamIdentity(**fields)

#    @classmethod
#    def get_fn(cls, app_name) -> str:
#        return cls._get_fn(app_name, cls.FN_TAIL)

    @classmethod
    def get_key(cls, app_name) -> bytes:
        with open(cls.get_fn()) as f:
            json_info = json.load(f)
        return bytes.fromhex(json_info["pub_key"])
