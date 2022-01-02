"""
Copyright 2021 Dean Hall.  See LICENSE for details.
"""

import datetime
import fnmatch
import functools
import hashlib
import json
import os
import os.path

import asn1                     # pip install asn1
from cryptography import x509   # pip install cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import app_data
from .ident import HamIdentity


ADDR_BIT_CNT = 128          # Default number of bits in an address
CERT_DURATION = 2 * 365     # X.509 certificate duration in days
APP_NAME = "ham_ident"      # Application name (for path to persistent storage)
OIDS = HamIdentity.REQUIRED_OIDS.union(HamIdentity.OPTIONAL_OIDS)


class HamCredentialBuilder():
    @classmethod
    def gen_personal_credentials(cls, ham_ident: HamIdentity, passphrase: bytes, cert_duration: int = CERT_DURATION):
        """Generates a keypair, writes a set of personal credential files and returns the list of files written."""
        app_path = app_data.get_app_data_path(APP_NAME)
        cls._clear_dir(app_path)    # WARNING: this may destroy a private key

        prv_key, pub_key = cls.gen_personal_keypair()
        callsign = ham_ident.pseudonym
        fns = []
        fns.append(cls._write_cert_to_x509(app_path, pub_key, prv_key, ham_ident, cert_duration))
        fns.append(cls._write_prv_key_to_pem(app_path, prv_key, callsign, passphrase))
        fns.append(cls._write_pub_key_to_der(app_path, pub_key, callsign))
        fns.append(cls._write_cred_to_json(app_path, pub_key, ham_ident))
        return fns

    @classmethod
    def gen_device_credentials(cls, ssid, passphrase, app_name):
        """Generates a keypair, writes a set of device credential files and returns the list of files written."""
        app_path = app_data.get_app_data_path(app_name)
        ham_ident = HamCredential.get_ident()
        callsign = ham_ident.pseudonym
        callsign_ssid = callsign + '-' + ssid
        dev_info = {}
        dev_info["pseudonym"] = callsign_ssid
        dev_info["commonName"] = ham_ident.commonName
        dev_info["emailAddress"] = ham_ident.emailAddress
        dev_ident = HamIdentity(**dev_info)
        prv_key, pub_key = cls.gen_device_keypair()
        fns = []
        fns.append(cls._write_prv_key_to_pem(app_path, prv_key, callsign_ssid, passphrase))
        fns.append(cls._write_pub_key_to_der(app_path, pub_key, callsign_ssid))
        fns.append(cls._write_cred_to_json(app_path, pub_key, dev_ident))
        return fns

    @classmethod
    def gen_personal_keypair(cls):
        """Returns a generated keypair.  The pub_key's hash is an fc/8 address
        (fc/7 is the unique local prefix).
        """
        return cls._gen_keypair_with_prefix("fc")

    @classmethod
    def gen_device_keypair(cls):
        """Returns a generated keypair.  The pub_key's hash is an fd/8 address
        (fc/7 is the unique local prefix).
        """
        return cls._gen_keypair_with_prefix("fd")

    @classmethod
    def gen_linklocal_keypair(cls):
        """Returns a generated keypair.  The pub_key's hash is an feb/12 address
        (feb/12 is a subset of fe8/10 the well-known link-local prefix).
        """
        return cls._gen_keypair_with_prefix("feb")

    @classmethod
    def _gen_keypair_with_prefix(cls, prefix):
        """Returns a generated keypair.  The pub_key's hash starts with the given prefix."""
        done = False
        while not done:
            prv_key = ec.generate_private_key(
                ec.SECP384R1(), default_backend())
            pub_key = prv_key.public_key()
            der_bytes = pub_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_key_bytes = cls._get_key_from_asn1(der_bytes)
            h = cls._hash(pub_key_bytes)
            done = h.hexdigest().startswith(prefix)
        return (prv_key, pub_key)

    @classmethod
    def _get_key_from_asn1(cls, der_bytes):
        """Returns the key bytes from a PublicKey instance
        whose DER encoding resembles:
        [U] SEQUENCE
            [U] SEQUENCE
                [U] OBJECT: 1.2.840.10045.2.1
                [U] OBJECT: 1.3.132.0.34
            [U] BIT STRING:<key bytes>
        """
        def rdparse_asn1(decoder):
            retval = None
            while not decoder.eof():
                tag = decoder.peek()
                if tag.typ == asn1.Types.Primitive:
                    tag, retval = decoder.read()
                    if tag.cls == asn1.Numbers.BitString:
                        break
                elif tag.typ == asn1.Types.Constructed:
                    decoder.enter()
                    retval = rdparse_asn1(decoder)
                    decoder.leave()
            return retval

        decoder = asn1.Decoder()
        decoder.start(der_bytes)
        pub_key_bytes = rdparse_asn1(decoder)
        # FIXME: pub_key_bytes is 98 bytes and always begins with "\x00\x04".
        # So I remove those two leading bytes and use the remaining 96 bytes.
        # Size agrees: 96 bytes == 768 bits == two 384 bit numbers (SECP384R1)
        pub_key_bytes = pub_key_bytes[2:]
        return pub_key_bytes

    @staticmethod
    def _hash(data):
        """Run SHA-512 on the data twice."""
        h = hashlib.sha512()
        h.update(data)
        h.update(h.digest())
        return h


    @staticmethod
    def _write_prv_key_to_pem(app_path, prv_key, callsign, passphrase):
        """Writes the private key to a .pem file.  Returns the filename."""
        fn = os.path.join(app_path, callsign + Credential.PRV_KEY_TAIL)
        with open(fn, "wb") as f:
            f.write(prv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase)))
        return fn

    @staticmethod
    def _write_pub_key_to_der(app_path, pub_key, callsign):
        """Writes the public key to a .der file.  Returns the filename."""
        fn = os.path.join(app_path, callsign + Credential.PUB_KEY_TAIL)
        with open(fn, "wb") as f:
            f.write(pub_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo))
        return fn

    @classmethod
    def _write_cert_to_x509(cls, app_path, pub_key, signing_key, ham_ident: HamIdentity, duration=CERT_DURATION):
        """Builds and writes a signed X.509 certificate to a file.  Returns the filename."""
        # Build a self-signed certificate (subject and issuer are the same)
        oid_name_attrs = [x509.NameAttribute(oid, getattr(ham_ident, oid._name)) for oid in OIDS if len(getattr(ham_ident, oid._name)) > 0]
        # oid_name_attrs = []
        # for oid in OIDS:
        #     name = oid._name
        #     if hasattr(ham_ident, name):
        #         val = getattr(ham_ident, name, "")
        #         oid_name_attrs.append(x509.NameAttribute(oid, val))
        subject = issuer = x509.Name(oid_name_attrs)
        cert = cls._build_cert(subject, issuer, pub_key, signing_key, duration)
        callsign = ham_ident.pseudonym

        # Write the certificate to a file.
        fn = os.path.join(app_path, callsign + HamCredential.CERT_TAIL)
        with open(fn, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return fn

    @staticmethod
    def _build_cert(subject, issuer, pub_key, signing_key, duration):
        now = datetime.datetime.utcnow()
        cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(pub_key) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(now) \
            .not_valid_after(
                now + datetime.timedelta(days=duration)) \
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False) \
            .sign(signing_key, hashes.SHA256(), default_backend())
        return cert

    @classmethod
    def _write_cred_to_json(cls, app_path, pub_key, ham_ident: HamIdentity):
        """Writes a JSON credential file including.  Returns the filename."""
        der_bytes = pub_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        pub_key_bytes = cls._get_key_from_asn1(der_bytes)
        callsign = ham_ident.pseudonym
        cred = {"commonName": ham_ident.commonName,
                "callsign": callsign,
                "pub_key": pub_key_bytes.hex()}

        fn = os.path.join(app_path, callsign + Credential.JSON_TAIL)
        with open(fn, "w") as f:
            json.dump(cred, f)
        return fn

    @classmethod
    def _clear_dir(cls, dir_path: str) -> None:
        for root, _, files in os.walk(dir_path):
            for fn in files:
                os.remove(os.path.join(root, fn))


class HamCredentialError(Exception):
    @classmethod
    def _assert(cls, test, msg):
        if not test:
            raise cls(msg)


class Credential:
    CERT_TAIL = "_cert.pem"
    PUB_KEY_TAIL = "_pub.der"
    PRV_KEY_TAIL = "_prv.pem"
    JSON_TAIL = "_cred.json"


class DeviceCredential(Credential):
    @classmethod
    def exists(cls, app_name: str, callsign: str = None) -> bool:
        try:
            return os.path.exists(cls.get_fn(callsign, app_name))
        except HamCredentialError:
            return False

    @classmethod
    def get_fn(cls, app_name: str, callsign: str = None) -> str:
        app_path = app_data.get_app_data_path(app_name)
        if callsign:
            fn = os.path.join(app_path, callsign + cls.CERT_TAIL)
        else:
            result = []
            for root, _, files in os.walk(app_path):
                for fn in files:
                    if fnmatch.fnmatch(fn, cls.CERT_TAIL):
                        result.append(os.path.join(root, fn))
            HamCredentialError._assert(len(result) == 1, "Expected one cert file")
            fn = result[0]
        return fn

    @classmethod
    def get_ident(cls, app_name: str, callsign: str = None):
        HamCredentialError._assert(cls.exists(callsign, app_name),
                                   "Credential file does not exist")
        pem_data = open(cls.get_fn(callsign), "rb").read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        fields = {}
        for oid in OIDS:
            val = cert.subject.get_attributes_for_oid(oid)[0].value
            if val:
                fields[oid._name] = val
        return HamIdentity(**fields)


class HamCredential(Credential):
    """HamCredential is an x509 certificate containing HamIdentity fields."""

    @classmethod
    def exists(cls, callsign: str = None) -> bool:
        try:
            return os.path.exists(cls.get_fn(callsign))
        except HamCredentialError:
            return False

    @classmethod
    def get_fn(cls, callsign: str = None) -> str:
        app_path = app_data.get_app_data_path(APP_NAME)
        if callsign:
            fn = os.path.join(app_path, callsign + cls.CERT_TAIL)
        else:
            result = []
            for root, _, files in os.walk(app_path):
                for fn in files:
                    if fn.endswith(cls.CERT_TAIL):
                        result.append(os.path.join(root, fn))
            HamCredentialError._assert(len(result) == 1, "Expected one cert file")
            fn = result[0]
        return fn

    @classmethod
    def get_ident(cls, callsign: str = None) -> HamIdentity:
        HamCredentialError._assert(cls.exists(callsign),
                                   "Credential file does not exist")
        pem_data = open(cls.get_fn(callsign), "rb").read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        fields = {}
        for oid in OIDS:
            attr = cert.subject.get_attributes_for_oid(oid)
            if len(attr) > 0:
                val = attr[0].value
                if val:
                    fields[oid._name] = val
        return HamIdentity(**fields)

    @classmethod
    def get_addr(cls,
                 callsign: str = None,
                 app_name: str = APP_NAME,
                 nmbr_bits: int = ADDR_BIT_CNT):
        """Returns an address that is computed from
        the public key found in the app's pre-made JSON file.
        """
        pub_key = cls._get_pub_key(callsign, app_name)
        addr = cls._get_addr_from_key(pub_key, nmbr_bits)
        addr_str = addr.hex()
        or_func = lambda x,y: x or y
        HamCredentialError._assert(
            functools.reduce(or_func, map(addr_str.startswith, ("fc", "fd", "feb"))),
            "Address doesn't have the expected prefix")
        return addr

    @classmethod
    def _get_pub_key(cls, callsign: str, app_name: str):
        app_path = app_data.get_app_data_path(app_name)
        fn = os.path.join(app_path, callsign + cls.PUB_KEY_TAIL)
        der_bytes = open(fn, "rb").read()
        pub_key_bytes = HamCredentialBuilder._get_key_from_asn1(der_bytes)
        return pub_key_bytes

    @classmethod
    def _get_addr_from_key(cls, pub_key: bytes, nmbr_bits: int):
        HamCredentialError._assert(nmbr_bits % 8 == 0,
                                   "Bit count must be a multiple of eight")
        h = HamCredentialBuilder._hash(pub_key)
        addr = h.digest()
        nmbr_bytes = nmbr_bits // 8
        return addr[:nmbr_bytes]


class HamJsonCredential(HamCredential):
    """HamJsonCredential is a JSON file containing HamIdentity fields and a public key."""
    CERT_TAIL = HamCredential.JSON_TAIL

    @classmethod
    def get_ident(cls, callsign: str, app_name: str = APP_NAME) -> HamIdentity:
        HamCredentialError._assert(cls.exists(callsign),
                                   "Credential file does not exist")
        with open(cls.get_fn(callsign)) as f:
            json_info = json.load(f)
        fields = {}
        for oid in HamIdentity.REQUIRED_OIDS:
            fields[oid._name] = json_info.get(oid._name, "")
        for oid in HamIdentity.OPTIONAL_OIDS:
            fields[oid._name] = json_info.get(oid._name, "")
        return HamIdentity(**fields)

    @classmethod
    def get_key(cls, app_name: str = APP_NAME )  -> bytes:
        with open(cls.get_fn()) as f:
            json_info = json.load(f)
        return bytes.fromhex(json_info["pub_key"])
