import dataclasses
import unittest

from ham_ident import HamIdentity, HamIdentityError


class TestHamIdentity(unittest.TestCase):
    def test_ctor_exception(self):
        with self.assertRaises(HamIdentityError):
            h = HamIdentity()

    def test_ctor(self):
        h = HamIdentity(commonName="Alice", emailAddress="alice@example.com", pseudonym="EX4MPL")
        self.assertEqual(h.commonName, "Alice")
        self.assertEqual(h.emailAddress, "alice@example.com")
        self.assertEqual(h.pseudonym, "EX4MPL")

    def test_immutability_exception(self):
        h = HamIdentity(commonName="Alice", emailAddress="alice@example.com", pseudonym="EX4MPL")
        with self.assertRaises(HamIdentityError):
            h.countryName = "US"

    def test_empty_required_field_exception(self):
        with self.assertRaises(HamIdentityError):
            h = HamIdentity(commonName="", emailAddress="alice@example.com", pseudonym="EX4MPL")

    def test_empty_optional_field(self):
        h = HamIdentity(commonName="Alice", emailAddress="alice@example.com", pseudonym="EX4MPL")
        self.assertEqual(h.countryName, "")

    def test_insufficient_fields_exception(self):
        with self.assertRaises(HamIdentityError):
            h = HamIdentity(pseudonym="EX4MPL")

    def test_pseudonym(self):
        h = HamIdentity(commonName="Alice", emailAddress="alice@example.com", pseudonym="EX4MPL")
        self.assertEqual(h.pseudonym, "EX4MPL")

    def test_attr(self):
        h = HamIdentity(commonName="Alice", emailAddress="alice@example.com", pseudonym="EX4MPL")
        self.assertEqual(h.commonName, "Alice")

    def test_all_fields(self):
        h = HamIdentity(
            commonName="Alice Last",
            emailAddress="alice@example.com",
            stateOrProvinceName="ST",
            countryName="US",
            postalCode="12345",
            pseudonym="EX4MPL"
        )
        self.assertEqual(h.commonName, "Alice Last")
        self.assertEqual(h.emailAddress, "alice@example.com")
        self.assertEqual(h.stateOrProvinceName, "ST")
        self.assertEqual(h.countryName, "US")
        self.assertEqual(h.postalCode, "12345")
        self.assertEqual(h.pseudonym, "EX4MPL")


if __name__ == '__main__':
    unittest.main()
