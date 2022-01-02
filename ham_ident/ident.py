"""
Copyright 2021 Dean Hall.  See LICENSE for details.
"""


from cryptography.x509.oid import NameOID


class HamIdentityError(Exception):
    @classmethod
    def _assert(cls, test, msg):
        if not test:
            raise cls(msg)


class HamIdentity():
    """HamIdentity defines a set of fields to use in an x509 certificate.
    The required fields are: commonName, emailAddress, pseudonym.
    The optional fields are: stateOrProvinceName, countryName, postcalCode.
    """
    REQUIRED_OIDS = {
        NameOID.COMMON_NAME,
        NameOID.EMAIL_ADDRESS,
        NameOID.PSEUDONYM
    }
    OPTIONAL_OIDS = {
        NameOID.STATE_OR_PROVINCE_NAME,
        NameOID.COUNTRY_NAME,
        NameOID.POSTAL_CODE
    }

    def __init__(self, **kwargs):
        """The kwargs to this constructor become the identity fields
        Optional keys: stateOrProvinceName countryName postalCode
        Required keys: commonName emailAddress
        """
        # Ensure kwargs has only keys whose names are expected OID names
        all_oids = self.REQUIRED_OIDS.union(self.OPTIONAL_OIDS)
        all_field_names = [getattr(oid, "_name") for oid in all_oids]
        arg_names = kwargs.keys()
        for arg_name in arg_names:
            HamIdentityError._assert(arg_name in all_field_names,
                                     f"Invalid OID name: {arg_name}. Expected a name from: {all_field_names}")

        required_field_names = [getattr(oid, "_name") for oid in self.REQUIRED_OIDS]
        for required_field_name in required_field_names:

            # Ensure kwargs has all the required keys
            HamIdentityError._assert(required_field_name in arg_names,
                                     f"Missing a required field: {required_field_name}")

            # Ensure required fields are not empty
            HamIdentityError._assert(kwargs[required_field_name] != "",
                                     f"Required field is empty: {required_field_name}")

        self.__dict__["_id_fields"] = kwargs

    def __getattr__(self, field_name: str):
        return self._id_fields.get(field_name, "")

    def __setattr__(self, name: str, value):
        raise HamIdentityError(f"'{self.__class__.__name__}' object does not support item assignment")
