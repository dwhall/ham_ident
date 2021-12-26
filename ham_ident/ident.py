"""
Copyright 2021 Dean Hall.  See LICENSE for details.
"""


from cryptography.x509.oid import NameOID


class HamIdentityError(Exception):
    pass


class HamIdentity():
    """HamIdentity defines a set of fields to use in an x509 certificate.
    The required fields are: givenName, emailAddress, pseudonym.
    The optional fields are: surname, stateOrProvinceName, countryName, postcalCode.
    """
    REQUIRED_OIDS = {
        NameOID.GIVEN_NAME,
        NameOID.EMAIL_ADDRESS,
        NameOID.PSEUDONYM
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
        # Ensure kwargs has only keys whose names are expected OID names
        all_field_names = [getattr(oid, "_name") for oid in self.REQUIRED_OIDS.union(self.OPTIONAL_OIDS)]
        arg_names = kwargs.keys()
        for arg_name in arg_names:
            if arg_name not in all_field_names:
                raise HamIdentityError("Invalid OID name: %s. Expected a name from: %s"
                                    % (arg_name, str(all_field_names)))

        required_field_names = [getattr(oid, "_name") for oid in self.REQUIRED_OIDS]
        for required_field_name in required_field_names:

            # Ensure kwargs has all the required keys
            if required_field_name not in arg_names:
                raise HamIdentityError("Missing a required field: %s"
                                    % required_field_name)

            # Ensure required field is not empty
            if kwargs[required_field_name] == "":
                raise HamIdentityError("Required field is empty: %s"
                                 % required_field_name)

        self.__dict__["_id_fields"] = kwargs

    def __getattr__(self, field_name):
        return self._id_fields.get(field_name, "")

    def __setattr__(self, name, value):
        raise HamIdentityError("'%s' object does not support item assignment"
                        % self.__class__.__name__)
