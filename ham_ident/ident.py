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
        """The kwargs to this constructor become the identity fields.
        Accepts keys: surname givenName callsign emailAddress country province
        postalcode.  The surname and emailAddress fields are required.
        """
        # Ensure kwargs has only keys whose names are expected OID names
        expected_oids = self.REQUIRED_OIDS.union(self.OPTIONAL_OIDS)
        oid_names = [getattr(oid, "_name") for oid in expected_oids]
        field_names = kwargs.keys()
        for k in field_names:
            if k not in oid_names:
                raise IdentityError(
                    "Invalid OID name: %s. Expected a name from: %s"
                    % (k, str(oid_names)))

        # Ensure kwargs has the required keys
        if "givenName" not in field_names or "emailAddress" not in field_names:
            raise IdentityError("Missing a required field: givenName or emailAddress")

        self._id_fields = kwargs

    def __getattr__(self, field_name):
        ret_val = self._id_fields.get(field_name, "")
        if ret_val is None:
            raise IdentityError("Field %s not present" % field_name)
        return ret_val


class HamIdentity(Identity):
    """HamIdentity uses the pseudonym field to hold the amateur radio callsign."""
    REQUIRED_OIDS = Identity.REQUIRED_OIDS.copy()
    REQUIRED_OIDS.add(NameOID.PSEUDONYM)
