"""
Copyright 2021 Dean Hall.  See LICENSE for details.
"""


from cryptography.x509.oid import NameOID


class IdentityError(Exception):
    pass


class Identity():
    """Identity defines the sets of required and optional fields
    that will be used in the x509 certificate.
    """
    REQUIRED_OIDS = {
        NameOID.GIVEN_NAME,
        NameOID.EMAIL_ADDRESS
    }
    OPTIONAL_OIDS = {
        NameOID.SURNAME,
        NameOID.STATE_OR_PROVINCE_NAME,
        NameOID.COUNTRY_NAME,
        NameOID.POSTAL_CODE
    }

    def __init__(self, **kwargs):
        """The kwargs to this constructor become the identity fields
        Optional keys: surname stateOrProvinceName countryName postalCode
        Required keys: givenName emailAddress
        """
        all_field_names = [getattr(oid, "_name") for oid in self.REQUIRED_OIDS.union(self.OPTIONAL_OIDS)]
        required_field_names = [getattr(oid, "_name") for oid in self.REQUIRED_OIDS]
        arg_names = kwargs.keys()

        # Ensure kwargs has only keys whose names are expected OID names
        for arg_name in arg_names:
            if arg_name not in all_field_names:
                raise IdentityError("Invalid OID name: %s. Expected a name from: %s"
                                    % (arg_name, str(all_field_names)))

        # Ensure kwargs has all the required keys
        for required_field_name in required_field_names:
            if required_field_name not in arg_names:
                raise IdentityError("Missing a required field: %s"
                                    % required_field_name)

        self._id_fields = kwargs

    def __getattr__(self, field_name):
        return self._id_fields.get(field_name, "")


class HamIdentity(Identity):
    """HamIdentity uses the pseudonym field to hold the amateur radio callsign."""
    REQUIRED_OIDS = Identity.REQUIRED_OIDS.copy()
    REQUIRED_OIDS.add(NameOID.PSEUDONYM)
