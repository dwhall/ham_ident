import dataclasses
import unittest

from ham_ident import HamIdentity, HamIdentityError


class TestHamIdentity(unittest.TestCase):
    def test_ctor_exception(self):
        with self.assertRaises(HamIdentityError):
            h = HamIdentity()

    def test_ctor(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", pseudonym="EX4MPL")
        self.assertEqual(h.givenName, "Given")
        self.assertEqual(h.emailAddress, "given@example.com")
        self.assertEqual(h.pseudonym, "EX4MPL")

    def test_immutability_exception(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", pseudonym="EX4MPL")
        with self.assertRaises(HamIdentityError):
            h.surname = "Last"

    def test_empty_required_field_exception(self):
        with self.assertRaises(HamIdentityError):
            h = HamIdentity(givenName="", emailAddress="given@example.com", pseudonym="EX4MPL")

    def test_empty_optional_field(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", surname="Last", pseudonym="EX4MPL")
        self.assertEqual(h.countryName, "")

    def test_surname_exception(self):
        with self.assertRaises(HamIdentityError):
            h = HamIdentity(surname="Last")

    def test_surname(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", pseudonym="EX4MPL", surname="Last")
        self.assertEqual(h.surname, "Last")

    def test_pseudonym_exception(self):
        with self.assertRaises(HamIdentityError):
            h = HamIdentity(pseudonym="EX4MPL")

    def test_pseudonym(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", pseudonym="EX4MPL")
        self.assertEqual(h.pseudonym, "EX4MPL")

    def test_attr(self):
        h = HamIdentity(givenName="Given", emailAddress="given@example.com", surname="Last", pseudonym="EX4MPL")
        self.assertEqual(h.givenName, "Given")

    def test_all(self):
        h = HamIdentity(
            givenName="Given",
            surname="Last",
            emailAddress="given@example.com",
            stateOrProvinceName="ST",
            countryName="US",
            postalCode="12345",
            pseudonym="EX4MPL"
        )
        self.assertEqual(h.givenName, "Given")
        self.assertEqual(h.surname, "Last")
        self.assertEqual(h.emailAddress, "given@example.com")
        self.assertEqual(h.stateOrProvinceName, "ST")
        self.assertEqual(h.countryName, "US")
        self.assertEqual(h.postalCode, "12345")
        self.assertEqual(h.pseudonym, "EX4MPL")


if __name__ == '__main__':
    unittest.main()
